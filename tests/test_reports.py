import unittest
from app.app import app, db, PhishingDomain, User
from app.extensions import bcrypt
from datetime import datetime, timedelta

class ReportsTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            # Create user and login
            hashed = bcrypt.generate_password_hash('testuser').decode('utf-8')
            user = User(username='testuser', password_hash=hashed)
            db.session.add(user)
            db.session.commit()

        self.app.post('/login', data=dict(
            username='testuser',
            password='testuser'
        ), follow_redirects=True)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_reports_generation(self):
        with app.app_context():
            # Create sample domains

            # Yellow (Monitoring)
            d1 = PhishingDomain(domain_name='yellow.com', date_entered=datetime.utcnow())

            # Red (Active & Login)
            d2 = PhishingDomain(domain_name='red.com', date_entered=datetime.utcnow(), is_active=True, has_login_page=True)

            # Purple (Takedown Requested)
            d3 = PhishingDomain(domain_name='purple.com', date_entered=datetime.utcnow(), manual_status='Takedown Requested')

            # Grey (Remediated)
            d4 = PhishingDomain(domain_name='grey.com', date_entered=datetime.utcnow() - timedelta(days=5), date_remediated=datetime.utcnow())

            # Out of date range
            d5 = PhishingDomain(domain_name='old.com', date_entered=datetime.utcnow() - timedelta(days=100))

            db.session.add_all([d1, d2, d3, d4, d5])
            db.session.commit()

        # Test fetching report for today (covering d1, d2, d3, d4)
        # Assuming d4 was entered 5 days ago, we'll pick a range that covers that
        today = datetime.utcnow().strftime('%Y-%m-%d')
        start_date = (datetime.utcnow() - timedelta(days=10)).strftime('%Y-%m-%d')

        # 1. Fetch all except Grey
        response = self.app.post('/reports', data={
            'start_date': start_date,
            'end_date': today,
            'statuses': ['Red', 'Yellow', 'Purple']
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/csv')
        csv_content = response.data.decode('utf-8')

        self.assertIn('red.com', csv_content)
        self.assertIn('yellow.com', csv_content)
        self.assertIn('purple.com', csv_content)
        self.assertNotIn('grey.com', csv_content)
        self.assertNotIn('old.com', csv_content)

        # 2. Fetch only Grey
        response = self.app.post('/reports', data={
            'start_date': start_date,
            'end_date': today,
            'statuses': ['Grey']
        })
        csv_content = response.data.decode('utf-8')
        self.assertIn('grey.com', csv_content)
        self.assertNotIn('red.com', csv_content)

        # 3. Fetch Red and Purple
        response = self.app.post('/reports', data={
            'start_date': start_date,
            'end_date': today,
            'statuses': ['Red', 'Purple']
        })
        csv_content = response.data.decode('utf-8')
        self.assertIn('red.com', csv_content)
        self.assertIn('purple.com', csv_content)
        self.assertNotIn('yellow.com', csv_content)

if __name__ == '__main__':
    unittest.main()
