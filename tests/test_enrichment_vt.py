import unittest
from unittest.mock import patch, MagicMock
from app.app import app, db, PhishingDomain
from app.utils import enrich_domain

class EnrichmentVTTestCase(unittest.TestCase):
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

    @patch('app.utils.VIRUSTOTAL_API_KEY', 'fake_vt_key')
    @patch('app.utils.check_vt_reputation')
    @patch('app.utils.fetch_whois_data') # Mock other calls to speed up
    @patch('app.utils.fetch_and_check_domain')
    @patch('app.utils.check_mx_record')
    @patch('app.utils.check_ns_record')
    def test_enrich_domain_vt_malicious(self, mock_ns, mock_mx, mock_scan, mock_whois, mock_vt):
        # Setup
        domain = PhishingDomain(domain_name='malicious.com')
        db.session.add(domain)
        db.session.commit()

        # Mocks
        mock_scan.return_value = None
        mock_mx.return_value = []
        mock_ns.return_value = []
        mock_whois.return_value = None

        # VT Mock
        mock_vt.return_value = {
            'malicious': 5,
            'suspicious': 2,
            'harmless': 80
        }

        # Execute
        enrich_domain(domain)

        # Verify
        mock_vt.assert_called_with('malicious.com', 'domain')
        self.assertEqual(domain.manual_status, 'Potential Phish')
        self.assertIn("VirusTotal Reputation: 5 malicious", domain.action_taken)
