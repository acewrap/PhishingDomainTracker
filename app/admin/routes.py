import json
import io
import csv
import secrets
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, send_file
from flask_login import login_required, current_user
from app.admin import admin_bp
from app.models import User, APIKey, PhishingDomain, ThreatTerm, EmailEvidence, EvidenceCorrelation
from app.extensions import db, bcrypt
from app.utils import admin_required, log_security_event, enrich_domain
from app.admin.forms import CSVUploadForm, RestoreForm, ThreatTermForm
from app.backup_service import generate_backup_data, perform_restore
from app.queue_service import add_task

@admin_bp.route('/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/reset/<int:id>', methods=['POST'])
@login_required
@admin_required
def reset_user_password(id):
    user = User.query.get_or_404(id)

    # Generate random password
    new_password = secrets.token_urlsafe(12)
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    user.password_hash = hashed_password
    user.password_expired = True
    user.failed_login_attempts = 0 # Reset failed attempts too
    db.session.commit()

    log_security_event('Password Change', current_user.username, request.remote_addr, 'info', target_user=user.username, action='admin_reset')

    flash(f'Password for {user.username} reset to: {new_password}. Please copy it now.', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/threat-terms', methods=['GET', 'POST'])
@login_required
@admin_required
def threat_terms():
    form = ThreatTermForm()
    if form.validate_on_submit():
        term = form.term.data.strip()
        if term:
            if not ThreatTerm.query.filter_by(term=term).first():
                new_term = ThreatTerm(term=term)
                db.session.add(new_term)
                db.session.commit()

                log_security_event(
                    'Threat String Added',
                    current_user.username,
                    request.remote_addr,
                    'info',
                    threat_string=term,
                    category='keyword'
                )

                flash(f'Term "{term}" added.', 'success')
            else:
                flash(f'Term "{term}" already exists.', 'warning')
        return redirect(url_for('admin.threat_terms'))

    terms = ThreatTerm.query.all()
    return render_template('admin/threat_terms.html', form=form, terms=terms)

@admin_bp.route('/threat-terms/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_threat_term(id):
    term = ThreatTerm.query.get_or_404(id)
    db.session.delete(term)
    db.session.commit()
    flash(f'Term "{term.term}" deleted.', 'success')
    return redirect(url_for('admin.threat_terms'))

@admin_bp.route('/evidence')
@login_required
@admin_required
def evidence_storage():
    evidence_list = EmailEvidence.query.order_by(EmailEvidence.submitted_at.desc()).all()
    return render_template('admin/evidence_storage.html', evidence_list=evidence_list)

@admin_bp.route('/evidence/<int:id>')
@login_required
@admin_required
def evidence_detail(id):
    evidence = EmailEvidence.query.get_or_404(id)
    headers = {}
    if evidence.headers:
        try:
            headers = json.loads(evidence.headers)
        except:
            headers = {'raw': evidence.headers}

    indicators = {}
    if evidence.extracted_indicators:
        try:
            indicators = json.loads(evidence.extracted_indicators)
        except:
            indicators = {'raw': evidence.extracted_indicators}

    return render_template('admin/evidence_detail.html', evidence=evidence, headers=headers, indicators=indicators)

@admin_bp.route('/evidence/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_evidence(id):
    evidence = EmailEvidence.query.get_or_404(id)

    # Delete correlations first
    EvidenceCorrelation.query.filter_by(evidence_id=id).delete()

    db.session.delete(evidence)
    db.session.commit()

    log_security_event('Evidence Deleted', current_user.username, request.remote_addr, 'info', filename=evidence.filename)
    flash(f'Evidence {evidence.filename} deleted.', 'success')
    return redirect(url_for('admin.evidence_storage'))

@admin_bp.route('/refresh_correlations', methods=['POST'])
@login_required
@admin_required
def refresh_correlations():
    add_task('refresh_correlations', {})
    flash('Correlation refresh task started.', 'info')
    log_security_event('Correlation Refresh Triggered', current_user.username, request.remote_addr, 'info')
    return redirect(url_for('admin.evidence_storage'))

@admin_bp.route('/data-management', methods=['GET'])
@login_required
@admin_required
def data_management():
    form = RestoreForm()
    return render_template('admin/backup_restore.html', form=form)

@admin_bp.route('/backup')
@login_required
@admin_required
def backup():
    log_security_event('Backup Created', current_user.username, request.remote_addr, 'info')
    backup_data = generate_backup_data()

    # Create JSON file in memory
    output = io.BytesIO()
    output.write(json.dumps(backup_data, indent=4).encode('utf-8'))
    output.seek(0)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(
        output,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'backup_{timestamp}.json'
    )

@admin_bp.route('/restore', methods=['POST'])
@login_required
@admin_required
def restore():
    form = RestoreForm()
    if form.validate_on_submit():
        file = form.file.data
        try:
            data = json.load(file)
            perform_restore(data)

            log_security_event('Database Restored', current_user.username, request.remote_addr, 'warning', status='Success')

            flash('Database restored successfully. You may need to log in again.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            flash(f'Error restoring database: {str(e)}', 'danger')
            return redirect(url_for('index'))

    flash('Invalid form submission.', 'danger')
    return redirect(url_for('index'))

@admin_bp.route('/import-csv', methods=['GET', 'POST'])
@login_required
@admin_required
def import_csv():
    form = CSVUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_input = csv.DictReader(stream)

        # Verify headers
        if not csv_input.fieldnames or 'domain' not in csv_input.fieldnames:
             flash('CSV must contain a "domain" column.', 'danger')
             return render_template('admin/import_csv.html', form=form)

        added_count = 0
        skipped_count = 0
        auto_enrich = form.auto_enrich.data

        for row in csv_input:
            domain_name = row.get('domain')
            if not domain_name:
                continue

            # Check for duplicate
            if PhishingDomain.query.filter_by(domain_name=domain_name).first():
                skipped_count += 1
                continue

            # Parse date
            date_str = row.get('entered_date')
            entered_date = datetime.utcnow()
            if date_str:
                try:
                    entered_date = datetime.strptime(date_str, '%Y-%m-%d')
                except ValueError:
                    pass # Default to now if invalid

            new_domain = PhishingDomain(
                domain_name=domain_name,
                date_entered=entered_date,
                is_active=True, # Default assumption for imports?
                manual_status='Yellow' # Default to monitored/suspicious
            )

            # Handle Category
            category = row.get('category', '').lower().strip()
            if category == 'green':
                new_domain.manual_status = 'Allowlisted'
            elif category == 'blue':
                new_domain.manual_status = 'Internal/Pentest'
            elif category == 'purple':
                new_domain.manual_status = 'Takedown Requested'
            elif category == 'grey':
                new_domain.date_remediated = entered_date
            elif category == 'red':
                new_domain.is_active = True
                new_domain.has_login_page = True
            elif category == 'orange':
                new_domain.has_mx_record = True
            elif category == 'yellow':
                new_domain.manual_status = 'Yellow'

            if auto_enrich:
                enrich_domain(new_domain)

            db.session.add(new_domain)
            log_security_event('Domain Imported', current_user.username, request.remote_addr, 'info', domain_name=new_domain.domain_name)
            added_count += 1

        try:
            db.session.commit()

            log_security_event(
                'CSV Import',
                current_user.username,
                request.remote_addr,
                'info',
                added_count=added_count,
                skipped_count=skipped_count
            )

            flash(f'Import complete: {added_count} added, {skipped_count} skipped.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Database error during import: {e}', 'danger')

    return render_template('admin/import_csv.html', form=form)
