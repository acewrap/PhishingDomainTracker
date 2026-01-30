import unittest
from app.app import app, db
from app.models import User, PhishingDomain
from app.extensions import bcrypt
from datetime import datetime

class DashboardTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            # Create user
            hashed = bcrypt.generate_password_hash('password').decode('utf-8')
            user = User(username='testuser', password_hash=hashed, is_admin=True)
            db.session.add(user)
            db.session.commit()

            # Create domains
            d1 = PhishingDomain(domain_name='test1.com', date_entered=datetime(2023, 1, 15), registrar='GoDaddy', asn_org='Google', ns_records='ns1.godaddy.com')
            d2 = PhishingDomain(domain_name='test2.com', date_entered=datetime(2023, 1, 20), registrar='Namecheap', asn_org='Cloudflare')
            db.session.add_all([d1, d2])
            db.session.commit()

        # Login
        self.client.post('/login', data=dict(
            username='testuser',
            password='password'
        ), follow_redirects=True)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_dashboard_route(self):
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Analytics Dashboard', response.data)
        self.assertIn(b'GoDaddy', response.data)
        self.assertIn(b'Namecheap', response.data)

    def test_quarterly_report_pdf(self):
        response = self.client.post('/dashboard/report/quarterly', data={'year': 2023, 'quarter': 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')

    def test_excel_export(self):
        response = self.client.post('/reports', data={
            'start_date': '2023-01-01',
            'end_date': '2023-12-31',
            'statuses': ['Yellow', 'Red', 'Orange', 'Purple', 'Grey', 'Blue', 'Green'],
            'export_format': 'excel'
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    unittest.main()
