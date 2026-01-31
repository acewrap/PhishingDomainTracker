import unittest
import json
import os
import io
from app.app import app, db
from app.models import User, EmailEvidence, EvidenceCorrelation, PhishingDomain
from app.extensions import bcrypt

class TestEvidenceUI(unittest.TestCase):
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

        # Create some Evidence
        self.ev1 = EmailEvidence(
            filename='test.eml',
            submitted_by=self.admin.id,
            headers=json.dumps({'Subject': 'Test Phish', 'From': 'bad@example.com'}),
            extracted_indicators=json.dumps({'urls': ['http://bad.com']}),
            body='Click here: http://bad.com'
        )
        db.session.add(self.ev1)

        # Create Domain and Correlation
        self.dom1 = PhishingDomain(domain_name='bad.com')
        db.session.add(self.dom1)
        db.session.commit() # Commit to get IDs

        self.corr1 = EvidenceCorrelation(
            evidence_id=self.ev1.id,
            domain_id=self.dom1.id,
            correlation_type='URL Match',
            details='Found in extracted indicators'
        )
        db.session.add(self.corr1)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def login_admin(self):
        return self.app.post('/login', data={'username': 'admin', 'password': 'password'}, follow_redirects=True)

    def login_user(self):
        return self.app.post('/login', data={'username': 'user', 'password': 'password'}, follow_redirects=True)

    def test_evidence_list_view(self):
        self.login_admin()
        resp = self.app.get('/admin/evidence')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'test.eml', resp.data)
        self.assertIn(b'bad.com', resp.data)
        # Check for new buttons
        self.assertIn(b'View', resp.data)
        self.assertIn(b'Delete', resp.data)

    def test_evidence_detail_view(self):
        self.login_admin()
        resp = self.app.get(f'/admin/evidence/{self.ev1.id}')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Evidence Detail: test.eml', resp.data)
        self.assertIn(b'Subject', resp.data)
        self.assertIn(b'Test Phish', resp.data)
        self.assertIn(b'http://bad.com', resp.data)
        self.assertIn(b'Correlated Domains', resp.data)

    def test_delete_evidence(self):
        self.login_admin()
        # Verify it exists
        self.assertIsNotNone(EmailEvidence.query.get(self.ev1.id))
        self.assertIsNotNone(EvidenceCorrelation.query.filter_by(evidence_id=self.ev1.id).first())

        resp = self.app.post(f'/admin/evidence/delete/{self.ev1.id}', follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'deleted', resp.data)

        # Verify deletion
        self.assertIsNone(EmailEvidence.query.get(self.ev1.id))
        self.assertIsNone(EvidenceCorrelation.query.filter_by(evidence_id=self.ev1.id).first())

    def test_redirect_logic(self):
        # Admin Upload Redirect
        self.login_admin()

        # Mock file upload
        data = {
            'file_upload': (io.BytesIO(b'From: test@test.com'), 'test.eml')
        }
        resp = self.app.post('/add', data=data, follow_redirects=False) # Don't follow to check location
        # Expect redirect to admin evidence
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/admin/evidence', resp.headers['Location'])

        # Logout Admin
        self.app.get('/logout', follow_redirects=True)

        # User Upload Redirect
        self.login_user()

        data = {
            'file_upload': (io.BytesIO(b'From: user@test.com'), 'test_user.eml')
        }
        resp = self.app.post('/add', data=data, follow_redirects=False)
        # Expect redirect to index
        self.assertEqual(resp.status_code, 302)
        # Should NOT be /admin/evidence
        self.assertFalse('/admin/evidence' in resp.headers['Location'])

if __name__ == '__main__':
    unittest.main()
