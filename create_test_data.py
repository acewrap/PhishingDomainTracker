import os
from flask import Flask
from app.extensions import db, migrate, bcrypt, login_manager
from app.models import User, PhishingDomain
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///domains.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'dev_secret_key'

db.init_app(app)
bcrypt.init_app(app)

with app.app_context():
    # Create test user
    user = User.query.filter_by(username='admin').first()
    if not user:
        user = User(username='admin', password_hash=bcrypt.generate_password_hash('password').decode('utf-8'), is_admin=True)
        db.session.add(user)

    # Create test domain with Shodan data
    domain = PhishingDomain.query.filter_by(domain_name='example.com').first()
    if not domain:
        domain = PhishingDomain(
            domain_name='example.com',
            asn_number='15169',
            asn_org='Google LLC',
            shodan_isp='Google Cloud',
            shodan_open_ports='[{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]',
            shodan_cves='[{"cve": "CVE-2021-1234", "description": "A sample CVE description."}]',
            favicon_mmh3='123456789'
        )
        db.session.add(domain)

    db.session.commit()
    print("Test data created successfully.")
