from apscheduler.schedulers.background import BackgroundScheduler
from app.models import PhishingDomain
from app.extensions import db
from app.utils import fetch_and_check_domain, check_mx_record, log_domain_event, http, logger, analyze_page_content, scan_page_content, fetch_whois_data, poll_pending_urlscans, adapter
from app.queue_service import add_task
import requests
from datetime import datetime
import socket
import json
from concurrent.futures import ThreadPoolExecutor

scheduler = BackgroundScheduler()

def append_action_note(domain, note):
    ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    new_note = f"[{ts}] {note}"
    if domain.action_taken:
        domain.action_taken += f"\n{new_note}"
    else:
        domain.action_taken = new_note

def init_scheduler(app):
    # Prevent adding jobs twice if reloader is active (though normally handled by run_simple(use_reloader=False) or check)
    if not scheduler.running:
        scheduler.add_job(check_purple_domains, 'interval', hours=6, args=[app])
        scheduler.add_job(check_red_domains, 'interval', hours=24, args=[app])
        scheduler.add_job(check_orange_domains, 'interval', hours=24, args=[app])
        scheduler.add_job(check_yellow_domains, 'interval', weeks=1, args=[app])
        scheduler.add_job(check_brown_domains, 'interval', weeks=1, args=[app])
        scheduler.add_job(check_grey_domains, 'interval', weeks=4, args=[app])
        # Poll Urlscan
        scheduler.add_job(poll_pending_urlscans, 'interval', minutes=2, args=[app])
        # Daily correlation refresh
        scheduler.add_job(trigger_correlation_refresh, 'interval', days=1, args=[app])
        scheduler.start()
        logger.info("Scheduler started.")

def trigger_correlation_refresh(app):
    with app.app_context():
        add_task('refresh_correlations', {})
        logger.info("Scheduled task: refresh_correlations triggered.")

def process_purple_domain(app, domain_id):
    # Create a local session to ensure thread safety
    local_http = requests.Session()
    local_http.mount("https://", adapter)
    local_http.mount("http://", adapter)
    local_http.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })

    with app.app_context():
        domain = PhishingDomain.query.get(domain_id)
        if not domain:
            return

        try:
            # Check 404 or no login/content
            found_active = False
            protocols = ['https://', 'http://']

            for protocol in protocols:
                url = f"{protocol}{domain.domain_name}"
                try:
                    resp = local_http.get(url, timeout=10, verify=False)
                    if resp.status_code == 200:
                        scan_res = scan_page_content(resp.text, base_url=resp.url)
                        if scan_res.get('is_login'):
                            found_active = True

                        if scan_res.get('blue_links'):
                            found_active = True
                            domain.manual_status = 'Confirmed Phish'
                            reason = f"Status changed to Confirmed Phish because linked images to Blue domains: {', '.join(scan_res['blue_links'])}"
                            append_action_note(domain, reason)
                            log_domain_event(domain.domain_name, 'Purple', 'Confirmed Phish', reason)

                        if found_active:
                            break
                except Exception:
                    pass

            if not found_active:
                # Move to Yellow (or Orange)
                old_status = 'Purple'
                domain.manual_status = None
                domain.date_remediated = None
                domain.is_active = False

                new_status = 'Orange' if domain.has_mx_record else 'Yellow'
                reason = "Status changed to Inactive because Login kit not detected (404 or content removed)"
                append_action_note(domain, reason)

                log_domain_event(domain.domain_name, old_status, new_status, reason)

            db.session.commit()

        except Exception as e:
            logger.error(f"Error checking purple domain {domain.domain_name}: {e}")
            db.session.rollback()

def check_purple_domains(app):
    with app.app_context():
        # Purple: Takedown Requested
        domain_ids = [d.id for d in PhishingDomain.query.filter_by(manual_status='Takedown Requested').all()]

    if not domain_ids:
        return

    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_purple_domain, app, d_id) for d_id in domain_ids]
        # Wait for all tasks to complete
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.error(f"Thread error in check_purple_domains: {e}")

def check_red_domains(app):
    with app.app_context():
        # Red: Active & Has Login Page (and not manual overridden)
        domains = PhishingDomain.query.filter(
            PhishingDomain.manual_status.is_(None),
            PhishingDomain.date_remediated.is_(None),
            PhishingDomain.is_active == True,
            PhishingDomain.has_login_page == True
        ).all()

        for domain in domains:
            try:
                with db.session.begin_nested():
                    # Update IP and verify reachable
                    reachable = False

                    # Get IP
                    try:
                        ip = socket.gethostbyname(domain.domain_name)
                        domain.ip_address = ip
                    except Exception:
                        pass

                    # Check reachability
                    protocols = ['https://', 'http://']
                    for protocol in protocols:
                        try:
                            resp = http.get(f"{protocol}{domain.domain_name}", timeout=10, verify=False)
                            if resp.status_code < 500:
                                reachable = True
                                break
                        except Exception:
                            pass

                    if not reachable:
                        old_status = 'Red'
                        domain.date_remediated = datetime.utcnow()
                        domain.is_active = False
                        reason = "Status changed to Remediated (Grey) because Domain unreachable"
                        append_action_note(domain, reason)
                        log_domain_event(domain.domain_name, old_status, 'Grey', reason)

                    db.session.flush()

            except Exception as e:
                logger.error(f"Error checking red domain {domain.domain_name}: {e}")

        db.session.commit()

def check_orange_domains(app):
    with app.app_context():
        # Orange: Has MX Record (and not Red/Purple/Grey/Blue/Green)
        domains = PhishingDomain.query.filter(
            PhishingDomain.manual_status.is_(None),
            PhishingDomain.date_remediated.is_(None),
            PhishingDomain.has_mx_record == True,
            (PhishingDomain.is_active == False) | (PhishingDomain.has_login_page == False)
        ).all()

        for domain in domains:
            try:
                with db.session.begin_nested():
                    current_records = check_mx_record(domain.domain_name) # Returns list
                    current_records_str = "\n".join(current_records) if current_records else None

                    old_records_str = domain.mx_records

                    if current_records_str != old_records_str:
                        reason = "MX Records Modified"
                        append_action_note(domain, reason)
                        domain.mx_records = current_records_str
                        if not current_records:
                            domain.has_mx_record = False
                        log_domain_event(domain.domain_name, 'Orange', 'Orange', reason)

                    db.session.flush()
            except Exception as e:
                logger.error(f"Error checking orange domain {domain.domain_name}: {e}")

        db.session.commit()

def check_yellow_domains(app):
    with app.app_context():
        # Yellow: Default
        domains = PhishingDomain.query.filter(
            PhishingDomain.manual_status.is_(None),
            PhishingDomain.date_remediated.is_(None),
            PhishingDomain.has_mx_record == False,
            (PhishingDomain.is_active == False) | (PhishingDomain.has_login_page == False)
        ).all()

        for domain in domains:
            try:
                with db.session.begin_nested():
                    protocols = ['https://', 'http://']
                    found_active = False
                    found_login = False
                    found_brown = False

                    for protocol in protocols:
                        try:
                            resp = http.get(f"{protocol}{domain.domain_name}", timeout=10, verify=False)
                            if resp.status_code == 200:
                                found_active = True
                                scan_res = scan_page_content(resp.text, base_url=resp.url)
                                if scan_res.get('is_login'):
                                    found_login = True

                                if scan_res.get('blue_links'):
                                    found_login = True
                                    domain.manual_status = 'Confirmed Phish'
                                    reason = f"Status changed to Confirmed Phish because linked images to Blue domains: {', '.join(scan_res['blue_links'])}"
                                    append_action_note(domain, reason)
                                    log_domain_event(domain.domain_name, 'Yellow', 'Confirmed Phish', reason)
                                    break # Stop processing this domain

                                if scan_res.get('is_for_sale'):
                                    found_brown = True
                                    domain.manual_status = 'Brown'
                                    # Fetch Whois Snapshot
                                    whois_data = fetch_whois_data(domain.domain_name)
                                    if whois_data:
                                        whois_record = whois_data.get('WhoisRecord', {})
                                        snapshot = {
                                            'registrant': whois_record.get('registrant', {}),
                                            'administrativeContact': whois_record.get('administrativeContact', {}),
                                            'technicalContact': whois_record.get('technicalContact', {}),
                                            'registrarName': whois_record.get('registrarName'),
                                            'createdDate': whois_record.get('createdDate')
                                        }
                                        domain.whois_snapshot = json.dumps(snapshot)

                                    reason = "Status changed to Brown (For Sale) based on page content."
                                    append_action_note(domain, reason)
                                    log_domain_event(domain.domain_name, 'Yellow', 'Brown', reason)
                                    break # Stop processing this domain

                                break
                        except Exception:
                            pass

                    # If we already handled it as Confirmed Phish or Brown, skip Red transition
                    if domain.manual_status in ['Confirmed Phish', 'Brown']:
                        continue

                    if found_active:
                        # Transition to Red
                        # If found_login is False but we need to transition to Red based on "200 OK" rule?
                        # The user said: "If the site returns a 200 OK or contains branding/password inputs, transition to 'Red'"
                        # This implies 200 OK is sufficient.

                        domain.is_active = True
                        domain.has_login_page = True # Force Red

                        reason = "Login/Threat detected" if found_login else "Site responded 200 OK"
                        full_reason = f"Status changed to Red because {reason}"
                        append_action_note(domain, full_reason)
                        log_domain_event(domain.domain_name, 'Yellow', 'Red', full_reason)

                    db.session.flush()

            except Exception as e:
                logger.error(f"Error checking yellow domain {domain.domain_name}: {e}")

        db.session.commit()

def check_brown_domains(app):
    with app.app_context():
        # Brown: Manual Status 'Brown' (For Sale)
        domains = PhishingDomain.query.filter_by(manual_status='Brown').all()

        for domain in domains:
            try:
                with db.session.begin_nested():
                    if not domain.whois_snapshot:
                        # No snapshot, cannot compare. Maybe create one?
                        # Or just log warning.
                        continue

                    current_data = fetch_whois_data(domain.domain_name)
                    if not current_data:
                        continue

                    try:
                        old_snapshot = json.loads(domain.whois_snapshot)
                    except json.JSONDecodeError:
                        continue

                    current_record = current_data.get('WhoisRecord', {})
                    current_snapshot = {
                        'registrant': current_record.get('registrant', {}),
                        'administrativeContact': current_record.get('administrativeContact', {}),
                        'technicalContact': current_record.get('technicalContact', {}),
                        'registrarName': current_record.get('registrarName'),
                        'createdDate': current_record.get('createdDate')
                    }

                    # Compare
                    changes = []
                    # Compare basic fields
                    if old_snapshot.get('registrarName') != current_snapshot.get('registrarName'):
                        changes.append(f"Registrar changed from '{old_snapshot.get('registrarName')}' to '{current_snapshot.get('registrarName')}'")

                    # Compare contacts (just name and email and org for simplicity)
                    for contact_type in ['registrant', 'administrativeContact', 'technicalContact']:
                        old_c = old_snapshot.get(contact_type, {})
                        new_c = current_snapshot.get(contact_type, {})

                        if old_c.get('name') != new_c.get('name'):
                            changes.append(f"{contact_type.capitalize()} Name changed from '{old_c.get('name')}' to '{new_c.get('name')}'")
                        if old_c.get('email') != new_c.get('email'):
                            changes.append(f"{contact_type.capitalize()} Email changed from '{old_c.get('email')}' to '{new_c.get('email')}'")
                        if old_c.get('organization') != new_c.get('organization'):
                            changes.append(f"{contact_type.capitalize()} Org changed from '{old_c.get('organization')}' to '{new_c.get('organization')}'")

                    if changes:
                        # Transition to Potential Phish (Red)
                        domain.manual_status = 'Potential Phish'
                        change_log = "; ".join(changes)
                        reason = f"Status changed to Potential Phish because Whois Data Changed: {change_log}"
                        append_action_note(domain, reason)
                        log_domain_event(domain.domain_name, 'Brown', 'Potential Phish', reason)

                    db.session.flush()

            except Exception as e:
                logger.error(f"Error checking brown domain {domain.domain_name}: {e}")

        db.session.commit()

def check_grey_domains(app):
    with app.app_context():
        # Grey: date_remediated IS NOT NULL
        domains = PhishingDomain.query.filter(PhishingDomain.date_remediated.isnot(None)).all()

        for domain in domains:
            try:
                with db.session.begin_nested():
                    protocols = ['https://', 'http://']
                    found_active = False

                    for protocol in protocols:
                        try:
                            resp = http.get(f"{protocol}{domain.domain_name}", timeout=10, verify=False)
                            if resp.status_code == 200:
                                found_active = True
                                scan_res = scan_page_content(resp.text, base_url=resp.url)
                                if scan_res.get('blue_links'):
                                    domain.manual_status = 'Confirmed Phish'
                                    reason = f"Status changed to Confirmed Phish because linked images to Blue domains: {', '.join(scan_res['blue_links'])}"
                                    append_action_note(domain, reason)
                                    log_domain_event(domain.domain_name, 'Grey', 'Confirmed Phish', reason)
                                break
                        except Exception:
                            pass

                    if found_active:
                        # Make Red
                        old_status = 'Grey'
                        domain.date_remediated = None
                        domain.is_active = True
                        domain.has_login_page = True # Force Red

                        reason = "Status changed to Red because Domain back to life"
                        append_action_note(domain, reason)
                        log_domain_event(domain.domain_name, old_status, 'Red', reason)

                    db.session.flush()

            except Exception as e:
                 logger.error(f"Error checking grey domain {domain.domain_name}: {e}")

        db.session.commit()
