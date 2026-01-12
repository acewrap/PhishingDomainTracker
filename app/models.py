from datetime import datetime
from flask_login import UserMixin
from app.extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    password_expired = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    api_keys = db.relationship('APIKey', backref='user', lazy=True)

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    secret_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)

class PhishingDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    registration_status = db.Column(db.String(100), nullable=True)
    registration_date = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    has_login_page = db.Column(db.Boolean, default=False)
    date_entered = db.Column(db.DateTime, default=datetime.utcnow)
    action_taken = db.Column(db.Text, nullable=True)
    date_remediated = db.Column(db.DateTime, nullable=True)
    screenshot_link = db.Column(db.String(500), nullable=True)
    registrar = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    urlscan_uuid = db.Column(db.String(100), nullable=True)
    has_mx_record = db.Column(db.Boolean, default=False)
    manual_status = db.Column(db.String(50), nullable=True)

    @property
    def threat_status(self):
        # 1. Manual Overrides (High Priority)
        if self.manual_status == 'Whitelisted':
            return 'Green'
        if self.manual_status == 'Internal/Pentest':
            return 'Blue'

        # 2. Remediated (Historical)
        if self.date_remediated:
            return 'Grey'

        # 3. Manual Overrides (Action Pending)
        if self.manual_status == 'Takedown Requested':
            return 'Purple'

        # 4. Automated Threat Detection
        if self.is_active and self.has_login_page:
            return 'Red'

        if self.has_mx_record:
            return 'Orange'

        # 5. Default / Monitoring
        return 'Yellow'
    
    def __repr__(self):
        return f'<PhishingDomain {self.domain_name}>'
