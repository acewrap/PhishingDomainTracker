import json
import io
import csv
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, send_file
from flask_login import login_required
from app.admin import admin_bp
from app.models import User, APIKey, PhishingDomain, ThreatTerm
from app.extensions import db, bcrypt
from app.utils import admin_required
from app.admin.forms import CSVUploadForm, RestoreForm, ThreatTermForm
from app.backup_service import generate_backup_data, perform_restore

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
            db.session.add(new_domain)
            added_count += 1

        try:
            db.session.commit()
            flash(f'Import complete: {added_count} added, {skipped_count} skipped.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Database error during import: {e}', 'danger')

    return render_template('admin/import_csv.html', form=form)
