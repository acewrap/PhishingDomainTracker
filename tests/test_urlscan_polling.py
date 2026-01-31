import unittest
from unittest.mock import patch, MagicMock
from app.app import app, db, PhishingDomain
from app.models import DomainScreenshot
from app.utils import process_urlscan_result, poll_pending_urlscans
from datetime import datetime
import json
import os

class UrlscanPollingTestCase(unittest.TestCase):
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

    @patch('app.utils.http.get')
    @patch('app.utils.URLSCAN_API_KEY', 'fake_key')
    def test_process_urlscan_result_pending(self, mock_get):
        # Setup domain with pending UUID
        domain = PhishingDomain(domain_name='pending.com', urlscan_uuid='uuid-123', urlscan_status='pending')
        db.session.add(domain)
        db.session.commit()

        # Mock 404 (Not Found / Pending)
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = process_urlscan_result(domain, app)
        self.assertFalse(result)
        self.assertEqual(domain.urlscan_status, 'pending')

    @patch('app.utils.http.get')
    @patch('app.utils.URLSCAN_API_KEY', 'fake_key')
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_process_urlscan_result_success(self, mock_file, mock_get):
        # Setup domain
        domain = PhishingDomain(domain_name='success.com', urlscan_uuid='uuid-456', urlscan_status='pending')
        db.session.add(domain)
        db.session.commit()

        # Mock Result Response (200)
        result_data = {
            'task': {'screenshotURL': 'http://urlscan.io/img.png'},
            'page': {
                'ip': '1.2.3.4',
                'asn': 'AS12345',
                'asnname': 'Test ASN',
                'country': 'US',
                'country_name': 'United States'
            },
            'lists': {},
            'verdicts': {
                'overall': {
                    'malicious': True,
                    'score': 100
                }
            }
        }

        # We need two responses: one for result JSON, one for image
        mock_resp_result = MagicMock()
        mock_resp_result.status_code = 200
        mock_resp_result.json.return_value = result_data

        mock_resp_img = MagicMock()
        mock_resp_img.status_code = 200
        mock_resp_img.content = b'fake_image_bytes'

        mock_get.side_effect = [mock_resp_result, mock_resp_img]

        # Call
        result = process_urlscan_result(domain, app)

        self.assertTrue(result)
        self.assertEqual(domain.urlscan_status, 'complete')
        self.assertEqual(domain.ip_address, '1.2.3.4')
        self.assertEqual(domain.asn_number, '12345')
        self.assertEqual(domain.asn_org, 'Test ASN')

        # Verify New Geolocation
        self.assertEqual(domain.geolocation_iso, 'US')
        self.assertEqual(domain.geolocation_country, 'United States')

        # Verify Status Upgrade
        self.assertEqual(domain.manual_status, 'Potential Phish')
        self.assertIn('Urlscan Verdict: Malicious', domain.action_taken)

        # Verify Screenshot Created
        screenshot = DomainScreenshot.query.filter_by(urlscan_uuid='uuid-456').first()
        self.assertIsNotNone(screenshot)
        self.assertEqual(screenshot.image_filename, 'urlscan_uuid-456.png')
        self.assertIn('"ip": "1.2.3.4"', screenshot.scan_data)

    @patch('app.utils.process_urlscan_result')
    def test_poll_pending_urlscans(self, mock_process):
        # Setup domains
        d1 = PhishingDomain(domain_name='d1.com', urlscan_uuid='u1', urlscan_status='pending')
        d2 = PhishingDomain(domain_name='d2.com', urlscan_uuid='u2', urlscan_status='complete') # Should not be picked
        d3 = PhishingDomain(domain_name='d3.com', urlscan_uuid='u3', urlscan_status='new')

        db.session.add_all([d1, d2, d3])
        db.session.commit()

        mock_process.return_value = True

        poll_pending_urlscans(app)

        # process_urlscan_result should be called for d1 and d3
        self.assertEqual(mock_process.call_count, 2)
