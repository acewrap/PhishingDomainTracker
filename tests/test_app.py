import unittest
import os
from app.app import app, db, PhishingDomain, User
from app.utils import enrich_domain
from app.extensions import bcrypt

class PhishingAppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        
        with app.app_context():
            db.create_all()
            # Create user and login
            hashed = bcrypt.generate_password_hash('testuser').decode('utf-8')
            user = User(username='testuser', password_hash=hashed)
            db.session.add(user)
            db.session.commit()

        self.client.post('/login', data=dict(
            username='testuser',
            password='testuser'
        ), follow_redirects=True)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_index_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Phishing Tracker', response.data)

    def test_add_domain(self):
        response = self.client.post('/add', data=dict(
            domain_name='test-phish.com',
            auto_enrich='on'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'test-phish.com', response.data)
        
        with app.app_context():
            domain = PhishingDomain.query.filter_by(domain_name='test-phish.com').first()
            self.assertIsNotNone(domain)
            self.assertEqual(domain.domain_name, 'test-phish.com')

    def test_update_domain(self):
        # Add a domain first
        with app.app_context():
            d = PhishingDomain(domain_name='update-me.com')
            db.session.add(d)
            db.session.commit()
            d_id = d.id

        response = self.client.post(f'/update/{d_id}', data=dict(
            action_taken='Takedown requested',
            is_active='on' 
        ), follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        
        with app.app_context():
            domain = PhishingDomain.query.get(d_id)
            self.assertEqual(domain.action_taken, 'Takedown requested')
            self.assertTrue(domain.is_active)
            self.assertFalse(domain.has_login_page) # was not in form

    def test_enrichment_mock(self):
        # This tests that the function runs without error even without keys
        # It relies on the logger warning if keys are missing
        with app.app_context():
            d = PhishingDomain(domain_name='enrich-me.com')
            enrich_domain(d)
            # Since we have no keys in env by default here, it should just pass through
            # We can't easily assert on logging without more setup, but we check no exception raised.
            self.assertEqual(d.domain_name, 'enrich-me.com')

if __name__ == '__main__':
    unittest.main()
