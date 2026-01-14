import unittest
import os
from unittest.mock import patch, MagicMock
from app.app import app, db, PhishingDomain, User
from app.extensions import bcrypt
from app.utils import report_to_vendors

class ReportingTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            hashed = bcrypt.generate_password_hash('correctpassword').decode('utf-8')
            user = User(username='testuser', password_hash=hashed)
            db.session.add(user)
            db.session.commit()

            self.user_id = user.id

            # Add a domain
            d = PhishingDomain(domain_name='evil.com')
            db.session.add(d)
            db.session.commit()
            self.domain_id = d.id

        self.client.post('/login', data=dict(
            username='testuser',
            password='correctpassword'
        ), follow_redirects=True)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    @patch('app.utils.http.post')
    def test_report_to_vendors_google_success(self, mock_post):
        # Patch the module variables directly since they are loaded at import time
        with patch('app.utils.GOOGLE_WEBRISK_KEY', 'fake_key'), \
             patch('app.utils.GOOGLE_PROJECT_ID', 'fake_project'):

            # Setup mock response
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_post.return_value = mock_resp

            with app.app_context():
                d = PhishingDomain(domain_name='evil.com')
                results = report_to_vendors(d)

                self.assertIn('Google Web Risk', results)
                self.assertEqual(results['Google Web Risk'], 'Success')

                # Verify call
                args, kwargs = mock_post.call_args
                self.assertIn('webrisk.googleapis.com', args[0])
                self.assertEqual(kwargs['json']['submission']['uri'], 'http://evil.com')

    @patch('app.utils.http.post')
    def test_report_to_vendors_urlhaus_success(self, mock_post):
        with patch('app.utils.URLHAUS_API_KEY', 'fake_key'):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {'query_status': 'ok'}
            mock_post.return_value = mock_resp

            with app.app_context():
                d = PhishingDomain(domain_name='evil.com')
                results = report_to_vendors(d)

                self.assertEqual(results['URLhaus'], 'Success')

    def test_report_route_success(self):
        with patch('app.app.report_to_vendors') as mock_report:
            mock_report.return_value = {'Google': 'Success'}

            response = self.client.post(f'/domain/{self.domain_id}/report_phishing', json={
                'password': 'correctpassword'
            })

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['success'], True)
            self.assertEqual(response.json['results']['Google'], 'Success')

            mock_report.assert_called_once()

    def test_report_route_invalid_password(self):
        response = self.client.post(f'/domain/{self.domain_id}/report_phishing', json={
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 403)
        self.assertIn('error', response.json)

    def test_report_route_missing_password(self):
        response = self.client.post(f'/domain/{self.domain_id}/report_phishing', json={
            'foo': 'bar'
        })
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
