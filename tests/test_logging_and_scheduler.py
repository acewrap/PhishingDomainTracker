import unittest
import json
import logging
from unittest.mock import MagicMock, patch
from app.app import app, db, PhishingDomain
from app.utils import log_security_event
from app.scheduler import append_action_note, check_yellow_domains

class LoggingSchedulerTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    @patch('app.utils.syslog_logger')
    def test_log_security_event_structure(self, mock_logger):
        log_security_event('Test Event', 'testuser', '1.1.1.1', domain_name='example.com')

        # Verify call args
        args, _ = mock_logger.info.call_args
        log_message = args[0]

        # Parse JSON part (after " - - ")
        json_part = log_message.split(' - - ')[1]
        data = json.loads(json_part)

        self.assertIn('User', data)
        self.assertIn('IP Address', data)
        self.assertIn('Phishing Domain', data)
        self.assertIn('Action Taken', data)

        self.assertEqual(data['User'], 'testuser')
        self.assertEqual(data['IP Address'], '1.1.1.1')
        self.assertEqual(data['Phishing Domain'], 'example.com')
        self.assertEqual(data['Action Taken'], 'Test Event')

    @patch('app.utils.syslog_logger')
    def test_log_security_event_na_domain(self, mock_logger):
        log_security_event('Test Event', 'testuser', '1.1.1.1')

        args, _ = mock_logger.info.call_args
        json_part = args[0].split(' - - ')[1]
        data = json.loads(json_part)

        self.assertEqual(data['Phishing Domain'], 'N/A')

    def test_append_action_note(self):
        domain = PhishingDomain(domain_name='note-test.com')
        db.session.add(domain)
        db.session.commit()

        append_action_note(domain, 'Test Note 1')
        self.assertIn('Test Note 1', domain.action_taken)
        self.assertIn('[', domain.action_taken) # Timestamp present

        append_action_note(domain, 'Test Note 2')
        self.assertIn('Test Note 1', domain.action_taken)
        self.assertIn('Test Note 2', domain.action_taken)
        self.assertIn('\n', domain.action_taken)

    @patch('app.scheduler.http')
    @patch('app.scheduler.log_domain_event')
    def test_scheduler_updates(self, mock_log_domain, mock_http):
        # Setup a yellow domain that should turn red
        domain = PhishingDomain(domain_name='yellow-to-red.com', manual_status=None, date_remediated=None, has_mx_record=False, is_active=False)
        db.session.add(domain)
        db.session.commit()

        # Mock HTTP response 200 OK
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>Hello</body></html>'
        mock_resp.url = 'http://yellow-to-red.com'
        mock_http.get.return_value = mock_resp

        check_yellow_domains(app)

        # Verify updates
        d = PhishingDomain.query.get(domain.id)
        self.assertTrue(d.is_active)
        self.assertTrue(d.has_login_page) # Force Red
        self.assertIn("Status changed to Red because", d.action_taken)

        # Verify log called
        mock_log_domain.assert_called_with('yellow-to-red.com', 'Yellow', 'Red', 'Status changed to Red because Site responded 200 OK')

if __name__ == '__main__':
    unittest.main()
