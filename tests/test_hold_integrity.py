import unittest
from unittest.mock import MagicMock, patch
from app.app import app, db
from app.models import PhishingDomain
from app.utils import fetch_hold_integrity_discovery

class TestHoldIntegrityIntegration(unittest.TestCase):
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

    @patch('app.utils.HOLD_INTEGRITY_API_KEY', 'fake_key')
    @patch('app.utils.HOLD_INTEGRITY_PROJECT_ID', 'fake_project')
    @patch('app.utils.http.get')
    def test_discovery_fetch_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": [
                {"domain": "test-hold-integrity.com", "status": "active", "timestamp": "2023-01-01"}
            ]
        }
        mock_get.return_value = mock_resp

        data = fetch_hold_integrity_discovery()
        self.assertIsNotNone(data)
        self.assertEqual(data['results'][0]['domain'], 'test-hold-integrity.com')

        # Verify URL construction
        args, kwargs = mock_get.call_args
        self.assertIn('/projects/fake_project/discovery', args[0])
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer fake_key')

    @patch('app.utils.HOLD_INTEGRITY_API_KEY', None)
    def test_missing_config(self):
        data = fetch_hold_integrity_discovery()
        self.assertIsNone(data)

if __name__ == '__main__':
    unittest.main()
