import unittest
from app.app import app
from app.extensions import db, bcrypt
from app.models import User
from flask_login import login_user

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False  # If using Flask-WTF
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

        # Create admin user
        hashed = bcrypt.generate_password_hash('admin').decode('utf-8')
        self.user = User(username='admin', password_hash=hashed, password_expired=True)
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self, username, password):
        return self.client.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def test_login_successful(self):
        response = self.login('admin', 'admin')
        self.assertIn(b'Your password has expired', response.data)
        # Should be redirected to change password
        self.assertIn(b'Change Password', response.data)

    def test_login_failed(self):
        response = self.login('admin', 'wrong')
        self.assertIn(b'Login Unsuccessful', response.data)

    def test_change_password(self):
        self.login('admin', 'admin')
        # Change password
        response = self.client.post('/change_password', data=dict(
            current_password='admin',
            new_password='newpass',
            confirm_password='newpass'
        ), follow_redirects=True)
        self.assertIn(b'Your password has been updated', response.data)

        # Verify db
        u = User.query.filter_by(username='admin').first()
        self.assertFalse(u.password_expired)
        self.assertTrue(bcrypt.check_password_hash(u.password_hash, 'newpass'))

    def test_admin_create_user(self):
        self.login('admin', 'admin')
        # Needs to change password first to access other routes if forced?
        # The 'check_password_expiration' middleware redirects if expired.
        # So I must change password first.
        self.client.post('/change_password', data=dict(
            current_password='admin',
            new_password='newpass',
            confirm_password='newpass'
        ), follow_redirects=True)

        response = self.client.post('/admin/create_user', data=dict(
            username='user2',
            password='user2pass'
        ), follow_redirects=True)
        self.assertIn(b'User user2 created', response.data)

        u2 = User.query.filter_by(username='user2').first()
        self.assertIsNotNone(u2)
        self.assertTrue(u2.password_expired)
