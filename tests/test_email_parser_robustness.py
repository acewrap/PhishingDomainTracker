
import unittest
from unittest.mock import MagicMock, patch, mock_open
import io
from app.email_parser import parse_email

class TestEmailParserRobustness(unittest.TestCase):

    def test_parse_eml_content(self):
        # Create a dummy EML content
        eml_content = (
            b"Subject: Test Email\r\n"
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"\r\n"
            b"This is the body with a url http://example.com"
        )

        # We pass the file stream directly to parse_email usually
        # But parse_email expects a stream.
        f = io.BytesIO(eml_content)
        result = parse_email(f, 'dummy.eml')

        self.assertEqual(result['headers']['Subject'], 'Test Email')
        self.assertIn('http://example.com', result['body'])
        self.assertIn('example.com', result['indicators']['domains'])

    @patch('app.email_parser.extract_msg.Message')
    def test_parse_msg_robustness(self, MockMessage):
        # Setup mock MSG
        mock_msg_instance = MockMessage.return_value
        mock_msg_instance.header = None # Simulate missing header property
        mock_msg_instance.headerDict = {'Subject': 'Test MSG'}
        mock_msg_instance.body = "Body with ip 1.1.1.1"

        # Mock file stream
        file_stream = MagicMock()

        result = parse_email(file_stream, 'test.msg')

        self.assertEqual(result['headers']['Subject'], 'Test MSG')
        self.assertIn('1.1.1.1', result['indicators']['ips'])

    @patch('app.email_parser.extract_msg.Message')
    def test_parse_msg_body_fallback(self, MockMessage):
        # Setup mock MSG with missing body but present htmlBody
        mock_msg_instance = MockMessage.return_value
        mock_msg_instance.header = {'Subject': 'HTML Only'}
        mock_msg_instance.body = None
        mock_msg_instance.htmlBody = b"<html><body>Link to http://html.com</body></html>"

        file_stream = MagicMock()

        result = parse_email(file_stream, 'html.msg')

        self.assertIn('http://html.com', result['body'])
        self.assertIn('html.com', result['indicators']['domains'])

if __name__ == '__main__':
    unittest.main()
