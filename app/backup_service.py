from datetime import datetime
from app.models import User, APIKey, PhishingDomain
from app.extensions import db

def generate_backup_data():
    """Generates a dictionary containing all database records."""
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

    return {
        'users': users,
        'api_keys': api_keys,
        'domains': domains
    }

def perform_restore(data):
    """Restores the database from the provided dictionary data.

    Raises ValueError if data structure is invalid.
    """
    if not all(k in data for k in ['users', 'api_keys', 'domains']):
        raise ValueError('Invalid backup file format. Missing required keys.')

    try:
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
    except Exception as e:
        db.session.rollback()
        raise e
