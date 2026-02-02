import unittest
from app.app import app, db
from app.models import EmailEvidence, PhishingDomain, EvidenceCorrelation
from app.email_parser import parse_email, extract_indicators
from app.correlation_engine import correlate_evidence
import io
import json

class EmailIngestionTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_extract_indicators(self):
        text = "Check this url: http://phishing.com/login and IP 1.2.3.4"
        indicators = extract_indicators(text)
        self.assertIn('http://phishing.com/login', indicators['urls'])
        self.assertIn('1.2.3.4', indicators['ips'])
        self.assertIn('phishing.com', indicators['domains'])

    def test_correlation(self):
        with app.app_context():
            # Setup Domain
            domain = PhishingDomain(domain_name='phishing.com', ip_address='1.2.3.4')
            db.session.add(domain)
            db.session.commit()

            # Setup Evidence
            evidence = EmailEvidence(
                filename='test.eml',
                extracted_indicators=json.dumps({
                    'domains': ['phishing.com'],
                    'ips': ['1.2.3.4']
                })
            )
            db.session.add(evidence)
            db.session.commit()

            # Run Correlation
            count = correlate_evidence(evidence.id)
            # Since create_correlation returns True only if new, and we iterate domains and IPs
            # Domain match: phishing.com -> match
            # IP match: 1.2.3.4 -> match
            # Total 2
            self.assertEqual(count, 2)

            # Check DB
            corrs = EvidenceCorrelation.query.filter_by(evidence_id=evidence.id).all()
            self.assertEqual(len(corrs), 2)

    def test_parse_eml(self):
        eml_content = b"""From: attacker@evil.com
To: victim@company.com
Subject: Urgent

Click here: http://phishing.com
"""
        with io.BytesIO(eml_content) as f:
            result = parse_email(f, 'test.eml')
            self.assertEqual(result['headers']['Subject'], 'Urgent')
            self.assertIn('http://phishing.com', result['indicators']['urls'])

if __name__ == '__main__':
    unittest.main()
