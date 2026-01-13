import unittest
import json
import io
import os
from datetime import datetime
from app.app import app, db
from app.models import User, APIKey, PhishingDomain
from app.extensions import bcrypt
from flask_login import login_user

class TestAdminFeatures(unittest.TestCase):
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

        # Create Normal User
        self.user = User(username='user', password_hash=hashed_pw, is_admin=False, password_expired=False)
        db.session.add(self.user)

        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def login_admin(self):
        return self.app.post('/login', data={'username': 'admin', 'password': 'password'}, follow_redirects=True)

    def login_user(self):
        return self.app.post('/login', data={'username': 'user', 'password': 'password'}, follow_redirects=True)

    def test_access_control(self):
        # Admin access
        self.login_admin()
        resp = self.app.get('/admin/backup')
        self.assertEqual(resp.status_code, 200)

        # Logout
        self.app.get('/logout', follow_redirects=True)

        # Non-admin access
        self.login_user()
        resp = self.app.get('/admin/backup')
        # Expect redirect to index because of admin_required
        self.assertEqual(resp.status_code, 302)
        # Verify redirect location is index
        # self.assertTrue('/' in resp.headers['Location'] or 'http://localhost/' in resp.headers['Location'])

    def test_backup(self):
        self.login_admin()

        # Add some data
        domain = PhishingDomain(domain_name='example.com', is_active=True)
        db.session.add(domain)
        db.session.commit()

        resp = self.app.get('/admin/backup')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)

        self.assertIn('users', data)
        self.assertIn('api_keys', data)
        self.assertIn('domains', data)
        self.assertEqual(len(data['domains']), 1)
        self.assertEqual(data['domains'][0]['domain_name'], 'example.com')

    def test_restore(self):
        self.login_admin()

        # Create backup data
        backup_data = {
            'users': [{
                'username': 'restored_admin',
                'password_hash': 'hash',
                'created_at': datetime.utcnow().isoformat(),
                'last_login_at': None,
                'password_expired': False,
                'is_admin': True
            }],
            'api_keys': [],
            'domains': [{
                'domain_name': 'restored.com',
                'date_entered': datetime.utcnow().isoformat()
            }]
        }

        data = json.dumps(backup_data)
        file = (io.BytesIO(data.encode()), 'backup.json')

        resp = self.app.post('/admin/restore', data={'file': file}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Check DB
        user = User.query.filter_by(username='restored_admin').first()
        self.assertIsNotNone(user)
        domain = PhishingDomain.query.filter_by(domain_name='restored.com').first()
        self.assertIsNotNone(domain)

        # Old data should be gone
        old_user = User.query.filter_by(username='user').first()
        self.assertIsNone(old_user)

    def test_import_csv(self):
        self.login_admin()

        csv_content = "domain,entered_date\nnew-domain.com,2023-10-01\nexisting.com,2023-10-02"
        file = (io.BytesIO(csv_content.encode()), 'import.csv')

        # Pre-create duplicate
        existing = PhishingDomain(domain_name='existing.com')
        db.session.add(existing)
        db.session.commit()

        resp = self.app.post('/admin/import-csv', data={'file': file}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        # Verify
        new_domain = PhishingDomain.query.filter_by(domain_name='new-domain.com').first()
        self.assertIsNotNone(new_domain)
        self.assertEqual(new_domain.date_entered.strftime('%Y-%m-%d'), '2023-10-01')

        # Count
        self.assertEqual(PhishingDomain.query.count(), 2)

if __name__ == '__main__':
    unittest.main()
