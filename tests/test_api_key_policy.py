import unittest
from app.app import app
from app.models import User, APIKey
from app.extensions import db, bcrypt
import secrets

class APIKeyPolicyTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

        with app.app_context():
            db.create_all()
            hashed = bcrypt.generate_password_hash('testuser').decode('utf-8')
            self.user = User(username='testuser', password_hash=hashed)
            db.session.add(self.user)
            db.session.commit()
            self.user_id = self.user.id

        self.client.post('/login', data=dict(
            username='testuser',
            password='testuser'
        ), follow_redirects=True)

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_single_key_policy_enforcement(self):
        # 1. Manually add multiple API keys for the user
        with app.app_context():
            user = User.query.get(self.user_id)
            for i in range(3):
                key = APIKey(
                    user_id=user.id,
                    access_key=f'key_{i}',
                    secret_hash='hash'
                )
                db.session.add(key)
            db.session.commit()

            self.assertEqual(APIKey.query.filter_by(user_id=user.id).count(), 3)

        # 2. Trigger key generation via Profile route
        # We need to send the submit button value to pass validation if needed,
        # but GenerateAPIKeyForm only has a SubmitField. Usually just POST is enough.
        response = self.client.post('/profile', data={'submit': 'Generate API Key'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # 3. Verify only ONE key exists now
        with app.app_context():
             keys = APIKey.query.filter_by(user_id=self.user_id).all()
             # If the bug exists (code only deletes .first()), we might have 3 (original 3 - 1 deleted + 1 new = 3) or similar.
             # We expect strictly 1.
             self.assertEqual(len(keys), 1, f"Should have exactly one key after generation, found {len(keys)}")
