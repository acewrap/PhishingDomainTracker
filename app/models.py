from datetime import datetime
from flask_login import UserMixin
from app.extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
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
    mx_records = db.Column(db.Text, nullable=True)
    manual_status = db.Column(db.String(50), nullable=True)

    # Correlation / Fingerprinting
    asn_number = db.Column(db.String(50), nullable=True)
    asn_org = db.Column(db.String(255), nullable=True)
    favicon_mmh3 = db.Column(db.String(100), nullable=True)
    jarm_hash = db.Column(db.String(255), nullable=True)
    html_artifacts = db.Column(db.Text, nullable=True)

    @property
    def threat_status(self):
        # 1. Manual Overrides (High Priority)
        if self.manual_status == 'Allowlisted':
            return 'Green'
        if self.manual_status == 'Internal/Pentest':
            return 'Blue'
        if self.manual_status == 'Confirmed Phish':
            return 'Red'

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

class ThreatTerm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(255), unique=True, nullable=False)

    def __repr__(self):
        return f'<ThreatTerm {self.term}>'

class EmailEvidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=True)
    headers = db.Column(db.Text, nullable=True)  # Stored as JSON string
    body = db.Column(db.Text, nullable=True)
    extracted_indicators = db.Column(db.Text, nullable=True)  # Stored as JSON string
    analysis_report = db.Column(db.Text, nullable=True)  # Stored as JSON string
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to user
    user = db.relationship('User', backref=db.backref('submissions', lazy=True))

    def __repr__(self):
        return f'<EmailEvidence {self.id} - {self.filename}>'

class EvidenceCorrelation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('email_evidence.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('phishing_domain.id'), nullable=False)
    correlation_type = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    evidence = db.relationship('EmailEvidence', backref=db.backref('correlations', lazy=True))
    domain = db.relationship('PhishingDomain', backref=db.backref('evidence_correlations', lazy=True))

    def __repr__(self):
        return f'<EvidenceCorrelation {self.evidence_id} <-> {self.domain_id}>'

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.Text, nullable=True)  # JSON payload
    status = db.Column(db.String(20), default='pending')
    result = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Task {self.id} {self.task_type} {self.status}>'
