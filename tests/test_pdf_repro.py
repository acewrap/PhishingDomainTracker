import unittest
from app.reporting import generate_quarterly_pdf
from app.models import PhishingDomain
from datetime import datetime
import sys

class TestPDFRepro(unittest.TestCase):
    def test_generate_pdf(self):
        # Create a mock object that mimics PhishingDomain or just use PhishingDomain without setting property
        d = PhishingDomain(domain_name='example.com', date_entered=datetime(2023, 1, 1))
        d.is_active = True
        d.has_login_page = True
        # manual_status defaults to 'New' or similar if not set?
        # Let's ensure threat_status returns something reasonable if accessed

        data = {
            'year': 2023,
            'quarter': 1,
            'start_date': datetime(2023, 1, 1),
            'end_date': datetime(2023, 3, 31),
            'total_domains': 10,
            'total_takedowns': 5,
            'takedown_rate': 50.0,
            'avg_remediation_hours': 24.0,
            'top_registrars': [('GoDaddy', 5)],
            'top_asns': [('Cloudflare', 5)],
            'domains': [d]
        }
        # We need app context for render_template
        from app.app import app
        app.config['SERVER_NAME'] = 'localhost' # Required for url_for if used
        with app.app_context():
            try:
                pdf_io = generate_quarterly_pdf(data)
                self.assertIsNotNone(pdf_io)
                print("PDF generated successfully")
            except Exception as e:
                print(f"Caught exception: {e}")
                import traceback
                traceback.print_exc()
                raise e

if __name__ == '__main__':
    unittest.main()
