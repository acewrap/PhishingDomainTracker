import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
import app.utils
from app.models import PhishingDomain

# Mock other calls to avoid network traffic/errors
app.utils.fetch_and_check_domain = MagicMock(return_value=False)
app.utils.check_mx_record = MagicMock(return_value=False)

class TestEnrichmentDateParsing(unittest.TestCase):

    def test_parse_created_date_iso(self):
        """Test parsing of standard ISO-like date string from WhoisXML"""
        domain = PhishingDomain(domain_name="example.com")

        # Mock response data
        mock_response_data = {
            'WhoisRecord': {
                'createdDate': '2023-01-15 12:00:00 UTC',
                'parseCode': 0
            }
        }

        with patch('app.utils.http.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = mock_response_data

            with patch('app.utils.WHOISXML_API_KEY', 'fake_key'):
                app.utils.enrich_domain(domain)

        self.assertEqual(domain.registration_date, datetime(2023, 1, 15, 12, 0, 0))

    def test_parse_created_date_registry_data(self):
        """Test fallback to registryData.createdDate"""
        domain = PhishingDomain(domain_name="example.com")

        mock_response_data = {
            'WhoisRecord': {
                'createdDate': '', # Empty here
                'registryData': {
                    'createdDate': '2022-12-25T08:30:00Z'
                },
                'parseCode': 0
            }
        }

        with patch('app.utils.http.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = mock_response_data

            with patch('app.utils.WHOISXML_API_KEY', 'fake_key'):
                app.utils.enrich_domain(domain)

        self.assertEqual(domain.registration_date, datetime(2022, 12, 25, 8, 30, 0))

    def test_parse_created_date_simple_date(self):
        """Test parsing of YYYY-MM-DD only"""
        domain = PhishingDomain(domain_name="example.com")

        mock_response_data = {
            'WhoisRecord': {
                'createdDate': '2021-05-20',
                'parseCode': 0
            }
        }

        with patch('app.utils.http.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = mock_response_data

            with patch('app.utils.WHOISXML_API_KEY', 'fake_key'):
                app.utils.enrich_domain(domain)

        self.assertEqual(domain.registration_date, datetime(2021, 5, 20, 0, 0, 0))

    def test_parse_created_date_invalid(self):
        """Test invalid date format"""
        domain = PhishingDomain(domain_name="example.com")

        mock_response_data = {
            'WhoisRecord': {
                'createdDate': 'Not a date',
                'parseCode': 0
            }
        }

        with patch('app.utils.http.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = mock_response_data

            with patch('app.utils.WHOISXML_API_KEY', 'fake_key'):
                app.utils.enrich_domain(domain)

        self.assertIsNone(domain.registration_date)

    def test_no_created_date(self):
        """Test missing createdDate"""
        domain = PhishingDomain(domain_name="example.com")

        mock_response_data = {
            'WhoisRecord': {
                'parseCode': 0
            }
        }

        with patch('app.utils.http.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = mock_response_data

            with patch('app.utils.WHOISXML_API_KEY', 'fake_key'):
                app.utils.enrich_domain(domain)

        self.assertIsNone(domain.registration_date)

if __name__ == '__main__':
    unittest.main()
