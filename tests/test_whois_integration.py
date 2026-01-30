import unittest
from unittest.mock import MagicMock, patch
from app.app import app, db
from app.models import PhishingDomain
from app.utils import enrich_domain
from datetime import datetime

class TestWhoisIntegration(unittest.TestCase):
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

    @patch('app.utils.WHOISXML_API_KEY', 'fake_key')
    @patch('app.utils.http.get')
    def test_whois_enrichment_success(self, mock_get):
        # Setup domain
        domain = PhishingDomain(domain_name='example.com')
        db.session.add(domain)
        db.session.commit()

        # Mock WhoisXML API response
        # Sample response based on typical WhoisXML structure
        mock_response_data = {
            'WhoisRecord': {
                'createdDate': '2000-01-01T12:00:00Z',
                'registrarName': 'Example Registrar, LLC',
                'parseCode': 0
            }
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_response_data

        # We need to handle multiple calls to http.get because enrich_domain might call other things
        # But we can inspect the call args to match the Whois API call

        def side_effect(*args, **kwargs):
            url = args[0] if args else kwargs.get('url')
            if 'whoisserver/WhoisService' in url:
                return mock_resp
            # Return a generic 404 or success for other calls (like fetch_and_check_domain)
            # checking domain content usually calls http.get too
            generic_resp = MagicMock()
            generic_resp.status_code = 404 # Simulate unreachable to skip other logic
            return generic_resp

        mock_get.side_effect = side_effect

        # Run enrichment
        enrich_domain(domain)

        # Verify API was called
        # We can't easily use assert_called_with because params might vary slightly or be in kwargs
        # So we iterate through calls
        called_api = False
        for call in mock_get.call_args_list:
            args, kwargs = call
            url = args[0] if args else kwargs.get('url')
            if url and 'whoisserver/WhoisService' in url:
                called_api = True
                params = kwargs.get('params', {})
                self.assertEqual(params.get('apiKey'), 'fake_key')
                self.assertEqual(params.get('domainName'), 'example.com')
                self.assertEqual(params.get('outputFormat'), 'JSON')
                self.assertEqual(params.get('ignoreRawTexts'), 1)
                break

        self.assertTrue(called_api, "WhoisXML API was not called")

        # Verify domain object updates
        self.assertEqual(domain.registrar, 'Example Registrar, LLC')
        self.assertEqual(domain.registration_status, 'Registered')
        # Date parsing check (2000-01-01)
        self.assertEqual(domain.registration_date.year, 2000)
        self.assertEqual(domain.registration_date.month, 1)
        self.assertEqual(domain.registration_date.day, 1)

if __name__ == '__main__':
    unittest.main()
