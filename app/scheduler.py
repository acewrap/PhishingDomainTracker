from apscheduler.schedulers.background import BackgroundScheduler
from app.models import PhishingDomain
from app.extensions import db
from app.utils import fetch_and_check_domain, check_mx_record, log_domain_event, http, logger, analyze_page_content, scan_page_content
from app.queue_service import add_task
import requests
from datetime import datetime
import socket

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
        scheduler.add_job(check_grey_domains, 'interval', weeks=4, args=[app])
        # Daily correlation refresh
        scheduler.add_job(trigger_correlation_refresh, 'interval', days=1, args=[app])
        scheduler.start()
        logger.info("Scheduler started.")

def trigger_correlation_refresh(app):
    with app.app_context():
        add_task('refresh_correlations', {})
        logger.info("Scheduled task: refresh_correlations triggered.")

def check_purple_domains(app):
    with app.app_context():
        # Purple: Takedown Requested
        domains = PhishingDomain.query.filter_by(manual_status='Takedown Requested').all()
        for domain in domains:
            try:
                # Check 404 or no login/content
                found_active = False
                protocols = ['https://', 'http://']

                for protocol in protocols:
                    url = f"{protocol}{domain.domain_name}"
                    try:
                        resp = http.get(url, timeout=10, verify=False)
                        if resp.status_code == 200:
                             scan_res = scan_page_content(resp.text, base_url=resp.url)
                             if scan_res.get('is_login'):
                                 found_active = True

                             if scan_res.get('blue_links'):
                                 found_active = True
                                 domain.manual_status = 'Confirmed Phish'
                                 reason = f"Status changed to Confirmed Phish because linked images to Blue domains: {', '.join(scan_res['blue_links'])}"
                                 append_action_note(domain, reason)
                                 db.session.commit()
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
                    db.session.commit()

                    log_domain_event(domain.domain_name, old_status, new_status, reason)

            except Exception as e:
                logger.error(f"Error checking purple domain {domain.domain_name}: {e}")

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
                    db.session.commit()
                    log_domain_event(domain.domain_name, old_status, 'Grey', reason)
                else:
                    db.session.commit()

            except Exception as e:
                logger.error(f"Error checking red domain {domain.domain_name}: {e}")

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
                current_records = check_mx_record(domain.domain_name) # Returns list
                current_records_str = "\n".join(current_records) if current_records else None

                old_records_str = domain.mx_records

                if current_records_str != old_records_str:
                     reason = "MX Records Modified"
                     append_action_note(domain, reason)
                     domain.mx_records = current_records_str
                     if not current_records:
                         domain.has_mx_record = False
                     db.session.commit()
                     log_domain_event(domain.domain_name, 'Orange', 'Orange', reason)
            except Exception as e:
                logger.error(f"Error checking orange domain {domain.domain_name}: {e}")

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
                protocols = ['https://', 'http://']
                found_active = False
                found_login = False

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
                                db.session.commit()
                                log_domain_event(domain.domain_name, 'Yellow', 'Confirmed Phish', reason)

                            break
                    except Exception:
                        pass

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
                    db.session.commit()

            except Exception as e:
                logger.error(f"Error checking yellow domain {domain.domain_name}: {e}")

def check_grey_domains(app):
    with app.app_context():
        # Grey: date_remediated IS NOT NULL
        domains = PhishingDomain.query.filter(PhishingDomain.date_remediated.isnot(None)).all()

        for domain in domains:
            try:
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
                                db.session.commit()
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
                    db.session.commit()

            except Exception as e:
                 logger.error(f"Error checking grey domain {domain.domain_name}: {e}")
