import unittest
from unittest.mock import MagicMock, patch
from app.app import app, db
from app.models import PhishingDomain
from app.utils import enrich_domain
from datetime import datetime

class TestIssueRepro(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    @patch('app.utils.URLSCAN_API_KEY', 'fake_key')
    @patch('app.utils.http.post')
    @patch('app.utils.fetch_and_check_domain')
    def test_repro_unreachable_domain_remediation(self, mock_fetch, mock_post):
        # Setup: Domain that was active and had a login page
        domain = PhishingDomain(
            domain_name='galileowebservice.online',
            is_active=True,
            has_login_page=True,
            date_remediated=None
        )
        db.session.add(domain)
        db.session.commit()

        # Mock Urlscan response (Success)
        # This checks if the code optimistically sets is_active=True just because Urlscan accepted it
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 200
        mock_post_resp.json.return_value = {'uuid': '123', 'result': 'http://urlscan.io/result'}
        mock_post.return_value = mock_post_resp

        # Mock fetch_and_check_domain to return None (Unreachable/Down)
        mock_fetch.return_value = None

        # Run Enrichment
        enrich_domain(domain)

        # Assertions
        # 1. Should be inactive because site is down
        self.assertFalse(domain.is_active, "Domain should be marked inactive if unreachable")

        # 2. Should not have login page because site is down
        self.assertFalse(domain.has_login_page, "Domain should not have login page if unreachable")

        # 3. Should be remediated (date set) because site is down
        self.assertIsNotNone(domain.date_remediated, "Date Remediated should be set if site is down")

        # Verify mocked calls were actually made
        mock_post.assert_called() # Urlscan was called
        mock_fetch.assert_called_with('galileowebservice.online')

if __name__ == '__main__':
    unittest.main()
