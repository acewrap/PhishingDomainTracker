import unittest
import json
import hashlib
from app.app import app
from app.models import User, APIKey, PhishingDomain
from app.extensions import db, bcrypt

class APIBackupTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        with app.app_context():
            db.create_all()

            # Create Admin
            admin_pass = bcrypt.generate_password_hash('adminpass').decode('utf-8')
            admin = User(username='admin', password_hash=admin_pass, is_admin=True)
            db.session.add(admin)
            db.session.flush()

            self.admin_access = 'admin_acc'
            self.admin_secret = 'admin_sec'
            admin_key = APIKey(
                user_id=admin.id,
                access_key=self.admin_access,
                secret_hash=hashlib.sha256(self.admin_secret.encode()).hexdigest()
            )
            db.session.add(admin_key)

            # Create Regular User
            user_pass = bcrypt.generate_password_hash('userpass').decode('utf-8')
            user = User(username='user', password_hash=user_pass, is_admin=False)
            db.session.add(user)
            db.session.flush()

            self.user_access = 'user_acc'
            self.user_secret = 'user_sec'
            user_key = APIKey(
                user_id=user.id,
                access_key=self.user_access,
                secret_hash=hashlib.sha256(self.user_secret.encode()).hexdigest()
            )
            db.session.add(user_key)

            # Add some data
            domain = PhishingDomain(domain_name='test.com')
            db.session.add(domain)
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_backup_admin(self):
        headers = {
            'X-API-Key': self.admin_access,
            'X-API-Secret': self.admin_secret
        }
        response = self.client.get('/api/v1/backup', headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('users', data)
        self.assertIn('api_keys', data)
        self.assertIn('domains', data)
        self.assertEqual(len(data['domains']), 1)
        self.assertEqual(data['domains'][0]['domain_name'], 'test.com')

    def test_backup_non_admin(self):
        headers = {
            'X-API-Key': self.user_access,
            'X-API-Secret': self.user_secret
        }
        response = self.client.get('/api/v1/backup', headers=headers)
        self.assertEqual(response.status_code, 403)

    def test_restore_admin(self):
        # 1. Get backup
        headers = {
            'X-API-Key': self.admin_access,
            'X-API-Secret': self.admin_secret
        }
        backup_response = self.client.get('/api/v1/backup', headers=headers)
        backup_data = backup_response.get_json()

        # Modify backup data to prove restore works (add a new domain)
        new_domain = {
            "domain_name": "restored.com",
            "is_active": True,
            "has_login_page": False,
            "has_mx_record": False
        }
        backup_data['domains'].append(new_domain)

        # 2. Restore
        restore_response = self.client.post('/api/v1/restore',
                                            headers=headers,
                                            json=backup_data)
        self.assertEqual(restore_response.status_code, 200)

        # 3. Verify
        with app.app_context():
            d1 = PhishingDomain.query.filter_by(domain_name='test.com').first()
            d2 = PhishingDomain.query.filter_by(domain_name='restored.com').first()
            self.assertIsNotNone(d1)
            self.assertIsNotNone(d2)

    def test_restore_non_admin(self):
        headers = {
            'X-API-Key': self.user_access,
            'X-API-Secret': self.user_secret
        }
        response = self.client.post('/api/v1/restore', headers=headers, json={})
        self.assertEqual(response.status_code, 403)

if __name__ == '__main__':
    unittest.main()
