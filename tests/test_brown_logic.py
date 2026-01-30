import unittest
from unittest.mock import patch, MagicMock
from app.app import app, db, PhishingDomain
from app.utils import scan_page_content
from app.scheduler import check_yellow_domains, check_brown_domains
import json

class BrownLogicTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_for_sale_detection(self):
        # Test 1: Content with "domain is for sale"
        html = "<html><body><h1>This domain is for sale</h1></body></html>"
        res = scan_page_content(html)
        self.assertTrue(res['is_for_sale'])

        # Test 2: Content with "buy this domain"
        html = "<div>Buy this domain now!</div>"
        res = scan_page_content(html)
        self.assertTrue(res['is_for_sale'])

        # Test 3: Normal content
        html = "<html><body><h1>Welcome to my blog</h1></body></html>"
        res = scan_page_content(html)
        self.assertFalse(res['is_for_sale'])

    @patch('app.scheduler.http.get')
    @patch('app.scheduler.fetch_whois_data')
    def test_check_yellow_to_brown(self, mock_fetch_whois, mock_http_get):
        # Setup Yellow domain
        d = PhishingDomain(domain_name='forsale.com', manual_status=None, has_mx_record=False)
        db.session.add(d)
        db.session.commit()

        # Mock HTTP response to simulate "For Sale" page
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>This domain is for sale</html>"
        mock_resp.url = "http://forsale.com"
        mock_http_get.return_value = mock_resp

        # Mock Whois fetch
        mock_fetch_whois.return_value = {
            'WhoisRecord': {
                'registrarName': 'GoDaddy',
                'registrant': {'name': 'John Doe'},
                'createdDate': '2023-01-01'
            }
        }

        # Run scheduler job
        check_yellow_domains(self.app)

        # Verify transition
        d = PhishingDomain.query.filter_by(domain_name='forsale.com').first()
        self.assertEqual(d.manual_status, 'Brown')
        self.assertEqual(d.threat_status, 'Brown')
        self.assertIsNotNone(d.whois_snapshot)
        snapshot = json.loads(d.whois_snapshot)
        self.assertEqual(snapshot['registrarName'], 'GoDaddy')

    @patch('app.scheduler.fetch_whois_data')
    def test_check_brown_to_red(self, mock_fetch_whois):
        # Setup Brown domain with snapshot
        snapshot = {
            'registrant': {'name': 'John Doe', 'email': 'john@example.com'},
            'registrarName': 'GoDaddy',
            'createdDate': '2023-01-01'
        }
        d = PhishingDomain(
            domain_name='changed.com',
            manual_status='Brown',
            whois_snapshot=json.dumps(snapshot)
        )
        db.session.add(d)
        db.session.commit()

        # Mock Whois fetch with CHANGE (Email changed)
        mock_fetch_whois.return_value = {
            'WhoisRecord': {
                'registrarName': 'GoDaddy',
                'registrant': {'name': 'John Doe', 'email': 'jane@example.com'}, # Changed
                'createdDate': '2023-01-01'
            }
        }

        # Run scheduler job
        check_brown_domains(self.app)

        # Verify transition
        d = PhishingDomain.query.filter_by(domain_name='changed.com').first()
        self.assertEqual(d.manual_status, 'Potential Phish')
        self.assertEqual(d.threat_status, 'Red')
        self.assertIn("Registrant Email changed", d.action_taken)

if __name__ == '__main__':
    unittest.main()
