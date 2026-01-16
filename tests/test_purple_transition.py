import unittest
from unittest.mock import patch, MagicMock
from app.app import app, db, PhishingDomain
from app.scheduler import check_purple_domains
from datetime import datetime

class TestPurpleTransition(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    @patch('app.scheduler.http.get')
    def test_purple_transitions_to_yellow_if_no_mx(self, mock_get):
        # Mock 404 response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with self.app.app_context():
            # Create a Purple domain (Takedown Requested)
            domain = PhishingDomain(
                domain_name='purple-to-yellow.com',
                manual_status='Takedown Requested',
                is_active=True,
                has_mx_record=False
            )
            db.session.add(domain)
            db.session.commit()

            # Run the check
            check_purple_domains(self.app)

            # Refresh domain
            domain = PhishingDomain.query.filter_by(domain_name='purple-to-yellow.com').first()

            # Assertions for new behavior
            self.assertIsNone(domain.manual_status, "Manual status should be cleared")
            self.assertIsNone(domain.date_remediated, "Date remediated should be None (not Grey)")
            self.assertEqual(domain.threat_status, 'Yellow', "Threat status should be Yellow")

    @patch('app.scheduler.http.get')
    def test_purple_transitions_to_orange_if_mx_exists(self, mock_get):
        # Mock 404 response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with self.app.app_context():
            # Create a Purple domain with MX records
            domain = PhishingDomain(
                domain_name='purple-to-orange.com',
                manual_status='Takedown Requested',
                is_active=True,
                has_mx_record=True,
                mx_records='v=spf1 ...'
            )
            db.session.add(domain)
            db.session.commit()

            # Run the check
            check_purple_domains(self.app)

            # Refresh domain
            domain = PhishingDomain.query.filter_by(domain_name='purple-to-orange.com').first()

            # Assertions for new behavior
            self.assertIsNone(domain.manual_status, "Manual status should be cleared")
            self.assertIsNone(domain.date_remediated, "Date remediated should be None (not Grey)")
            self.assertEqual(domain.threat_status, 'Orange', "Threat status should be Orange")

if __name__ == '__main__':
    unittest.main()
