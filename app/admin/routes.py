import json
import io
import csv
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, send_file
from flask_login import login_required
from app.admin import admin_bp
from app.models import User, APIKey, PhishingDomain
from app.extensions import db, bcrypt
from app.utils import admin_required
from app.admin.forms import CSVUploadForm, RestoreForm

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
    # Serialize Users
    users = []
    for user in User.query.all():
        u_data = {
            'username': user.username,
            'password_hash': user.password_hash,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
            'password_expired': user.password_expired,
            'is_admin': user.is_admin
        }
        users.append(u_data)

    # Serialize API Keys
    api_keys = []
    for key in APIKey.query.all():
        k_data = {
            'user_username': key.user.username, # Store username to resolve relationship
            'access_key': key.access_key,
            'secret_hash': key.secret_hash,
            'created_at': key.created_at.isoformat() if key.created_at else None,
            'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None
        }
        api_keys.append(k_data)

    # Serialize Phishing Domains
    domains = []
    for domain in PhishingDomain.query.all():
        d_data = {
            'domain_name': domain.domain_name,
            'registration_status': domain.registration_status,
            'registration_date': domain.registration_date.isoformat() if domain.registration_date else None,
            'is_active': domain.is_active,
            'has_login_page': domain.has_login_page,
            'date_entered': domain.date_entered.isoformat() if domain.date_entered else None,
            'action_taken': domain.action_taken,
            'date_remediated': domain.date_remediated.isoformat() if domain.date_remediated else None,
            'screenshot_link': domain.screenshot_link,
            'registrar': domain.registrar,
            'ip_address': domain.ip_address,
            'urlscan_uuid': domain.urlscan_uuid,
            'has_mx_record': domain.has_mx_record,
            'manual_status': domain.manual_status
        }
        domains.append(d_data)

    backup_data = {
        'users': users,
        'api_keys': api_keys,
        'domains': domains
    }

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

            # Verify structure
            if not all(k in data for k in ['users', 'api_keys', 'domains']):
                 flash('Invalid backup file format.', 'danger')
                 return redirect(url_for('index')) # Or admin page

            # --- DANGER ZONE: WIPE DATA ---
            # Order: APIKey (fk to User), User, PhishingDomain
            APIKey.query.delete()
            User.query.delete()
            PhishingDomain.query.delete()

            # --- RESTORE ZONE ---

            # 1. Restore Users
            # We need to map usernames to new IDs for API Key restoration
            user_map = {}
            for u_data in data['users']:
                user = User(
                    username=u_data['username'],
                    password_hash=u_data['password_hash'],
                    created_at=datetime.fromisoformat(u_data['created_at']) if u_data['created_at'] else None,
                    last_login_at=datetime.fromisoformat(u_data['last_login_at']) if u_data['last_login_at'] else None,
                    password_expired=u_data['password_expired'],
                    is_admin=u_data['is_admin']
                )
                db.session.add(user)
                db.session.flush() # Generate ID
                user_map[user.username] = user.id

            # 2. Restore API Keys
            for k_data in data['api_keys']:
                user_id = user_map.get(k_data['user_username'])
                if user_id:
                    api_key = APIKey(
                        user_id=user_id,
                        access_key=k_data['access_key'],
                        secret_hash=k_data['secret_hash'],
                        created_at=datetime.fromisoformat(k_data['created_at']) if k_data['created_at'] else None,
                        last_used_at=datetime.fromisoformat(k_data['last_used_at']) if k_data['last_used_at'] else None
                    )
                    db.session.add(api_key)

            # 3. Restore Domains
            for d_data in data['domains']:
                domain = PhishingDomain(
                    domain_name=d_data['domain_name'],
                    registration_status=d_data.get('registration_status'),
                    registration_date=datetime.fromisoformat(d_data['registration_date']) if d_data.get('registration_date') else None,
                    is_active=d_data.get('is_active', False),
                    has_login_page=d_data.get('has_login_page', False),
                    date_entered=datetime.fromisoformat(d_data['date_entered']) if d_data.get('date_entered') else datetime.utcnow(),
                    action_taken=d_data.get('action_taken'),
                    date_remediated=datetime.fromisoformat(d_data['date_remediated']) if d_data.get('date_remediated') else None,
                    screenshot_link=d_data.get('screenshot_link'),
                    registrar=d_data.get('registrar'),
                    ip_address=d_data.get('ip_address'),
                    urlscan_uuid=d_data.get('urlscan_uuid'),
                    has_mx_record=d_data.get('has_mx_record', False),
                    manual_status=d_data.get('manual_status')
                )
                db.session.add(domain)

            db.session.commit()
            flash('Database restored successfully. You may need to log in again.', 'success')
            return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
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
