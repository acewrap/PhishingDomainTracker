import unittest
from app.app import app
from app.extensions import db, bcrypt
from app.models import User, APIKey
import hashlib
from datetime import datetime

class ApiTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

        # Create user and api key
        hashed = bcrypt.generate_password_hash('user').decode('utf-8')
        self.user = User(username='user', password_hash=hashed)
        db.session.add(self.user)
        db.session.commit()

        self.access_key = 'testaccess'
        self.secret_key = 'testsecret'
        secret_hash = hashlib.sha256(self.secret_key.encode()).hexdigest()

        self.api_key = APIKey(
            user_id=self.user.id,
            access_key=self.access_key,
            secret_hash=secret_hash
        )
        db.session.add(self.api_key)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_get_domains_no_auth(self):
        response = self.client.get('/api/v1/domains')
        self.assertEqual(response.status_code, 401)

    def test_get_domains_auth(self):
        headers = {
            'X-API-Key': self.access_key,
            'X-API-Secret': self.secret_key
        }
        response = self.client.get('/api/v1/domains', headers=headers)
        self.assertEqual(response.status_code, 200)

    def test_post_domain_auth(self):
        headers = {
            'X-API-Key': self.access_key,
            'X-API-Secret': self.secret_key
        }
        response = self.client.post('/api/v1/domains', json={'domain_name': 'api-phish.com'}, headers=headers)
        self.assertEqual(response.status_code, 201)
        self.assertIn(b'api-phish.com', response.data)
