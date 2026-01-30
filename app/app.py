from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
from app.extensions import db, migrate, bcrypt, login_manager
from app.models import PhishingDomain, User, EmailEvidence
from app.utils import enrich_domain, report_to_vendors, log_security_event, find_related_sites, fetch_whois_data
from app.forms import AddDomainForm
from app.queue_service import add_task
from app.reporting import generate_evidence_pdf
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid
import csv
import io
import sqlite3
import sqlalchemy
from flask import Response, send_file
from flask_wtf.csrf import CSRFProtect
from app.scheduler import init_scheduler
from whitenoise import WhiteNoise
import time

app = Flask(__name__)
csrf = CSRFProtect(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# WhiteNoise for static files
if os.path.isdir(os.path.join(app.root_path, 'static')):
    app.wsgi_app = WhiteNoise(app.wsgi_app, root=os.path.join(app.root_path, 'static'), prefix='static/')

@app.cli.command("run-scheduler")
def run_scheduler_command():
    """Runs the scheduler in a separate process."""
    init_scheduler(app)
    # The scheduler is background, so we must keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

@app.cli.command("run-worker")
def run_worker_command():
    """Runs the background task worker."""
    from app.queue_service import process_next_task
    import logging

    # Ensure uploads dir exists
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    logger = logging.getLogger(__name__)
    logger.info("Worker started...")
    try:
        while True:
            processed = False
            # Use app_context to ensure DB session is valid
            processed = process_next_task()

            if not processed:
                time.sleep(5) # Poll interval
            else:
                 time.sleep(1) # Small delay
    except KeyboardInterrupt:
        logger.info("Worker stopped.")

# Security Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Ensure SESSION_COOKIE_SECURE is True in production (when serving over HTTPS)
if os.environ.get('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///domains.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')

db.init_app(app)
migrate.init_app(app, db)
bcrypt.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

from app.auth import auth
from app.api import api_v1
from app.admin import admin_bp

csrf.exempt(api_v1)
app.register_blueprint(auth)
app.register_blueprint(api_v1)
app.register_blueprint(admin_bp, url_prefix='/admin')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def check_password_expiration():
    from flask_login import current_user
    if current_user.is_authenticated and current_user.password_expired:
        if request.endpoint and request.endpoint not in ['auth.change_password', 'auth.logout', 'static']:
            flash('Your password has expired. Please change it.', 'warning')
            return redirect(url_for('auth.change_password'))

@app.route('/')
@login_required
def index():
    domains = PhishingDomain.query.order_by(PhishingDomain.date_entered.desc()).all()
    return render_template('index.html', domains=domains)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_domain():
    form = AddDomainForm()
    if form.validate_on_submit():
        # Handle File Upload
        if form.file_upload.data:
            file = form.file_upload.data
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"

            # Ensure uploads directory
            upload_dir = os.path.join(app.root_path, '..', 'uploads')
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)

            filepath = os.path.join(upload_dir, unique_filename)
            file.save(filepath)

            # Create Evidence Record
            evidence = EmailEvidence(
                filename=filename,
                submitted_by=current_user.id
            )
            db.session.add(evidence)
            db.session.commit()

            # Add Task
            add_task('process_email', {'evidence_id': evidence.id, 'filepath': filepath})

            log_security_event('Email Uploaded', current_user.username, request.remote_addr, 'info', filename=filename)
            flash(f'File {filename} uploaded and processing started.', 'success')

            # Determine redirect - maybe to Evidence Storage page?
            # Since that page isn't fully built/linked in menu yet, maybe index or stay?
            # But the plan says "Web UI: Admin Evidence Storage" is next step.
            # Assuming it will exist:
            return redirect(url_for('index')) # Or evidence storage

        # Handle Domain Name
        if form.domain_name.data:
            domain_name = form.domain_name.data.strip()

            # Check if exists
            existing = PhishingDomain.query.filter_by(domain_name=domain_name).first()
            if existing:
                flash(f'Domain {domain_name} already exists.', 'warning')
                return redirect(url_for('domain_details', id=existing.id))

            new_domain = PhishingDomain(domain_name=domain_name)

            # Optional: auto-enrich on add
            if form.auto_enrich.data:
                    enrich_domain(new_domain)

            db.session.add(new_domain)
            db.session.commit()

            log_security_event('Domain Added', current_user.username, request.remote_addr, 'info', domain_name=domain_name)

            flash(f'Domain {domain_name} added successfully.', 'success')
            return redirect(url_for('index'))

    return render_template('add_domain.html', form=form)

@app.route('/domain/<int:id>')
@login_required
def domain_details(id):
    domain = PhishingDomain.query.get_or_404(id)

    # Infrastructure Correlations
    related_sites = find_related_sites(id)

    can_report = bool(os.environ.get('PHISHTANK_API_KEY') or
                      os.environ.get('URLHAUS_API_KEY') or
                      (os.environ.get('GOOGLE_WEBRISK_KEY') and os.environ.get('GOOGLE_PROJECT_ID')))

    return render_template('domain_detail.html', domain=domain, can_report=can_report, related_sites=related_sites)

@app.route('/enrich/<int:id>', methods=['POST'])
@login_required
def enrich_domain_route(id):
    domain = PhishingDomain.query.get_or_404(id)
    enrich_domain(domain)
    db.session.commit()
    log_security_event('Enrichment Triggered', current_user.username, request.remote_addr, 'info', domain_name=domain.domain_name)
    flash(f'Enrichment triggered for {domain.domain_name}', 'info')
    return redirect(url_for('domain_details', id=domain.id))

@app.route('/update/<int:id>', methods=['POST'])
@login_required
def update_domain(id):
    domain = PhishingDomain.query.get_or_404(id)
    
    # Capture old values
    old_values = {
        'action_taken': domain.action_taken,
        'date_remediated': domain.date_remediated,
        'is_active': domain.is_active,
        'has_login_page': domain.has_login_page,
        'manual_status': domain.manual_status
    }

    domain.action_taken = request.form.get('action_taken')
    
    # Handle date_remediated
    date_rem_str = request.form.get('date_remediated')
    if date_rem_str:
        try:
             # HTML date input returns YYYY-MM-DD
             domain.date_remediated = datetime.strptime(date_rem_str, '%Y-%m-%d')
        except ValueError:
             pass # Keep old value or ignore error
    else:
        domain.date_remediated = None

    domain.is_active = 'is_active' in request.form
    domain.has_login_page = 'has_login_page' in request.form
    domain.manual_status = request.form.get('manual_status')
    
    db.session.commit()

    # Compare and log
    changes = []
    if old_values['action_taken'] != domain.action_taken:
        changes.append(('action_taken', old_values['action_taken'], domain.action_taken))

    if old_values['date_remediated'] != domain.date_remediated:
        changes.append(('date_remediated', str(old_values['date_remediated']), str(domain.date_remediated)))

    if old_values['is_active'] != domain.is_active:
        changes.append(('is_active', old_values['is_active'], domain.is_active))

    if old_values['has_login_page'] != domain.has_login_page:
        changes.append(('has_login_page', old_values['has_login_page'], domain.has_login_page))

    if old_values['manual_status'] != domain.manual_status:
        changes.append(('manual_status', old_values['manual_status'], domain.manual_status))

        # If manually set to Brown, ensure we have a snapshot for tracking
        if domain.manual_status == 'Brown':
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

    for field, old, new in changes:
         log_security_event(
             'Domain Record Changed',
             current_user.username,
             request.remote_addr,
             'info',
             domain_name=domain.domain_name,
             field_name=field,
             old_value=old,
             new_value=new,
             action_type='user'
         )

    flash('Domain updated successfully.', 'success')
    return redirect(url_for('domain_details', id=domain.id))

@app.route('/domain/<int:id>/report_phishing', methods=['POST'])
@login_required
def report_phishing_route(id):
    domain = PhishingDomain.query.get_or_404(id)
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'error': 'Password required'}), 400

    password = data['password']

    # Verify password
    if not bcrypt.check_password_hash(current_user.password_hash, password):
        return jsonify({'error': 'Invalid password'}), 403

    # Perform reporting
    results = report_to_vendors(domain)

    log_security_event('Phishing Reported to Vendors', current_user.username, request.remote_addr, 'info', domain_name=domain.domain_name, results=results)

    return jsonify({'success': True, 'results': results})

@app.route('/enrich_domains', methods=['POST'])
@login_required
def enrich_domains():
    # Manual CSRF protection for non-WTF form
    # Or just use WTF if we update index.html to use it
    # But since it's a simple list, we can just ensure CSRF token is present in the form
    # and let Flask-WTF global protection handle it?
    # Yes, CSRFProtect(app) protects all POST requests.
    # The form in index.html must include <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    domain_ids = request.form.getlist('domain_ids')
    if domain_ids:
        domains = PhishingDomain.query.filter(PhishingDomain.id.in_(domain_ids)).all()
        for domain in domains:
            enrich_domain(domain)
            log_security_event('Enrichment Triggered', current_user.username, request.remote_addr, 'info', domain_name=domain.domain_name)
        db.session.commit()
        flash(f'Enrichment triggered for {len(domains)} domains.', 'success')
    else:
        flash('No domains selected for enrichment.', 'warning')
    return redirect(url_for('index'))

@app.route('/delete_domains', methods=['POST'])
@login_required
def delete_domains():
    domain_ids = request.form.getlist('domain_ids')
    if domain_ids:
        # Check if "delete_all" or similar logic is needed, but assuming ID list for now
        domains = PhishingDomain.query.filter(PhishingDomain.id.in_(domain_ids)).all()
        for domain in domains:
            log_security_event('Domain Deleted', current_user.username, request.remote_addr, 'info', domain_name=domain.domain_name)
            db.session.delete(domain)
        db.session.commit()
        flash(f'{len(domains)} domains deleted successfully.', 'success')
    else:
        flash('No domains selected for deletion.', 'warning')
    return redirect(url_for('index'))

@app.route('/evidence/report/<int:id>')
@login_required
def download_evidence_report(id):
    pdf_io = generate_evidence_pdf(id)
    if not pdf_io:
        flash('Report generation failed or evidence not found.', 'danger')
        return redirect(url_for('index'))

    return send_file(
        pdf_io,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'evidence_report_{id}.pdf'
    )

@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    if request.method == 'POST':
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        selected_statuses = request.form.getlist('statuses')

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('reports'))

        # Query domains within the date range
        domains = PhishingDomain.query.filter(
            PhishingDomain.date_entered >= start_date,
            PhishingDomain.date_entered <= end_date
        ).all()

        # Filter by computed threat_status
        filtered_domains = [d for d in domains if d.threat_status in selected_statuses]

        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Headers
        headers = [
            'ID', 'Domain Name', 'Registration Status', 'Is Active',
            'Has Login Page', 'Date Entered', 'Action Taken',
            'Date Remediated', 'Screenshot Link', 'Registrar',
            'IP Address', 'Urlscan UUID', 'Has MX Record',
            'Manual Status', 'Threat Status'
        ]
        writer.writerow(headers)

        for d in filtered_domains:
            writer.writerow([
                d.id,
                d.domain_name,
                d.registration_status,
                d.is_active,
                d.has_login_page,
                d.date_entered.isoformat() if d.date_entered else '',
                d.action_taken,
                d.date_remediated.isoformat() if d.date_remediated else '',
                d.screenshot_link,
                d.registrar,
                d.ip_address,
                d.urlscan_uuid,
                d.has_mx_record,
                d.manual_status,
                d.threat_status
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=report.csv"}
        )

    return render_template('reports.html')

if __name__ == '__main__':
    # Initialize scheduler
    init_scheduler(app)
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    app.run(debug=debug_mode, host='0.0.0.0', port=8080)
