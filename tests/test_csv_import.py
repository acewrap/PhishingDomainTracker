import unittest
import io
from unittest.mock import patch
from app.app import app, db
from app.models import User, PhishingDomain
from app.extensions import bcrypt

class TestCSVImport(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        self.ctx = app.app_context()
        self.ctx.push()
        db.create_all()

        # Create Admin User
        hashed_pw = bcrypt.generate_password_hash('password').decode('utf-8')
        self.admin = User(username='admin', password_hash=hashed_pw, is_admin=True, password_expired=False)
        db.session.add(self.admin)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def login_admin(self):
        return self.app.post('/login', data={'username': 'admin', 'password': 'password'}, follow_redirects=True)

    @patch('app.admin.routes.enrich_domain')
    def test_import_with_categories_and_enrichment(self, mock_enrich):
        self.login_admin()

        csv_content = """domain,category,entered_date
green.com,green,2023-01-01
blue.com,blue,2023-01-01
purple.com,purple,2023-01-01
grey.com,grey,2023-01-01
red.com,red,2023-01-01
orange.com,orange,2023-01-01
yellow.com,yellow,2023-01-01
default.com,,2023-01-01
"""
        file = (io.BytesIO(csv_content.encode()), 'import.csv')

        # Post with auto_enrich='y' to simulate checked box
        data = {
            'file': file,
            'auto_enrich': 'y'
        }

        resp = self.app.post('/admin/import-csv', data=data, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Check Calls to enrich_domain
        # Should be called for all 8 domains
        self.assertEqual(mock_enrich.call_count, 8)

        # Verify Categories
        green = PhishingDomain.query.filter_by(domain_name='green.com').first()
        self.assertEqual(green.manual_status, 'Allowlisted')

        blue = PhishingDomain.query.filter_by(domain_name='blue.com').first()
        self.assertEqual(blue.manual_status, 'Internal/Pentest')

        purple = PhishingDomain.query.filter_by(domain_name='purple.com').first()
        self.assertEqual(purple.manual_status, 'Takedown Requested')

        grey = PhishingDomain.query.filter_by(domain_name='grey.com').first()
        self.assertIsNotNone(grey.date_remediated)

        red = PhishingDomain.query.filter_by(domain_name='red.com').first()
        self.assertTrue(red.is_active)
        self.assertTrue(red.has_login_page)

        orange = PhishingDomain.query.filter_by(domain_name='orange.com').first()
        self.assertTrue(orange.has_mx_record)

        yellow = PhishingDomain.query.filter_by(domain_name='yellow.com').first()
        self.assertEqual(yellow.manual_status, 'Yellow')

    @patch('app.admin.routes.enrich_domain')
    def test_import_without_enrichment(self, mock_enrich):
        self.login_admin()

        csv_content = "domain\nno-enrich.com"
        file = (io.BytesIO(csv_content.encode()), 'import.csv')

        # Send without 'auto_enrich' field (simulating unchecked)
        data = {
            'file': file
        }

        resp = self.app.post('/admin/import-csv', data=data, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Should NOT be called
        mock_enrich.assert_not_called()

        domain = PhishingDomain.query.filter_by(domain_name='no-enrich.com').first()
        self.assertIsNotNone(domain)

if __name__ == '__main__':
    unittest.main()
