from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class PhishingDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    registration_status = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    has_login_page = db.Column(db.Boolean, default=False)
    date_entered = db.Column(db.DateTime, default=datetime.utcnow)
    action_taken = db.Column(db.Text, nullable=True)
    date_remediated = db.Column(db.DateTime, nullable=True)
    screenshot_link = db.Column(db.String(500), nullable=True)
    registrar = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    urlscan_uuid = db.Column(db.String(100), nullable=True)
    
    def __repr__(self):
        return f'<PhishingDomain {self.domain_name}>'
