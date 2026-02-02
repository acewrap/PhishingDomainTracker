import unittest
from unittest.mock import MagicMock, patch
import io
from app.email_parser import parse_email

class TestEmailParserRobustness(unittest.TestCase):

    @patch('app.email_parser.extract_msg.Message')
    def test_standard_msg_extraction(self, mock_msg_class):
        # Setup mock
        mock_instance = MagicMock()
        mock_instance.headerDict = {'Subject': 'Test Subject', 'From': 'sender@example.com'}
        mock_instance.body = "This is the body."
        mock_instance.htmlBody = None
        mock_msg_class.return_value = mock_instance

        # Execute
        result = parse_email(io.BytesIO(b"fake data"), "test.msg")

        # Verify
        self.assertEqual(result['headers']['Subject'], 'Test Subject')
        self.assertEqual(result['body'], "This is the body.")

    @patch('app.email_parser.extract_msg.Message')
    def test_raw_header_string_fallback(self, mock_msg_class):
        # Setup mock: headerDict is empty, header is a string
        mock_instance = MagicMock()
        mock_instance.headerDict = {}
        mock_instance.header = "Subject: Raw Subject\nFrom: raw@example.com\n\n"
        mock_instance.body = "Body"
        mock_msg_class.return_value = mock_instance

        # Execute
        result = parse_email(io.BytesIO(b"fake data"), "test.msg")

        # Verify
        self.assertEqual(result['headers']['Subject'], 'Raw Subject')

    @patch('app.email_parser.extract_msg.Message')
    def test_transport_property_fallback(self, mock_msg_class):
        # Setup mock: headerDict empty, header empty, but property exists
        mock_instance = MagicMock()
        mock_instance.headerDict = {}
        mock_instance.header = None

        # Mock property for 007D001F (unicode)
        mock_prop = MagicMock()
        mock_prop.value = "Subject: Transport Subject\nFrom: trans@example.com\n\n"

        # Configure getProps to return dictionary containing the key
        mock_instance.getProps.return_value = {'007D001F': mock_prop}

        mock_instance.body = "Body"
        mock_msg_class.return_value = mock_instance

        # Execute
        result = parse_email(io.BytesIO(b"fake data"), "test.msg")

        # Verify
        self.assertEqual(result['headers']['Subject'], 'Transport Subject')

    @patch('app.email_parser.extract_msg.Message')
    def test_rtf_body_fallback(self, mock_msg_class):
        # Setup mock: body empty, htmlBody empty, rtfBody present
        mock_instance = MagicMock()
        mock_instance.headerDict = {'Subject': 'Test'}
        mock_instance.body = None
        mock_instance.htmlBody = None
        mock_instance.rtfBody = "RTF Content"
        mock_msg_class.return_value = mock_instance

        # Execute
        result = parse_email(io.BytesIO(b"fake data"), "test.msg")

        # Verify
        self.assertEqual(result['body'], "RTF Content")
