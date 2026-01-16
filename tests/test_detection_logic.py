import unittest
from unittest.mock import MagicMock, patch
import app.utils
from app.utils import fetch_and_check_domain, analyze_page_content

class TestDetectionLogic(unittest.TestCase):

    @patch('app.utils.http.get')
    def test_spa_detection_with_external_script(self, mock_get):
        # Setup mocks

        # Mock response for the main page
        # Note: No "password" text here, only in the script
        main_page_html = '<html><head><script src="/assets/app.js"></script></head><body>Loading...</body></html>'
        mock_response_main = MagicMock()
        mock_response_main.status_code = 200
        mock_response_main.text = main_page_html
        mock_response_main.url = "http://example.com/"

        # Mock response for the script
        script_content = 'var fields = { user: "username", pass: "password" };'
        mock_response_script = MagicMock()
        mock_response_script.status_code = 200
        mock_response_script.text = script_content
        mock_response_script.url = "http://example.com/assets/app.js"

        # Configure side_effect to return appropriate response based on URL
        def side_effect(url, *args, **kwargs):
            # Simple logic to distinguish requests
            if 'app.js' in url:
                return mock_response_script
            return mock_response_main

        mock_get.side_effect = side_effect

        # Run detection
        # We expect it to find "password" in the script and return True.
        # This will currently FAIL because the code doesn't fetch scripts.
        result = fetch_and_check_domain('example.com')
        self.assertTrue(result, "Should detect password in external script")

    @patch('app.utils.http.get')
    def test_raw_html_detection(self, mock_get):
        # Test detection in raw HTML (e.g. inside attributes or inline scripts)
        # where soup.get_text() might miss it.

        html_content = '<html><body><div data-field="password"></div></body></html>'
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = html_content
        mock_response.url = "http://rawtest.com/"

        mock_get.return_value = mock_response

        result = fetch_and_check_domain('rawtest.com')
        self.assertTrue(result, "Should detect password in raw HTML attributes")

if __name__ == '__main__':
    unittest.main()
