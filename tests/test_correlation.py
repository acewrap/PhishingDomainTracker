import unittest
from app.app import app as flask_app, db
from app.models import PhishingDomain
from app.utils import scan_page_content, find_related_sites
import json

class CorrelationTestCase(unittest.TestCase):
    def setUp(self):
        flask_app.config['TESTING'] = True
        flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        flask_app.config['WTF_CSRF_ENABLED'] = False
        self.client = flask_app.test_client()

        with flask_app.app_context():
            db.create_all()

            # Setup Blue Domain
            blue = PhishingDomain(domain_name='internal.com', manual_status='Internal/Pentest')
            db.session.add(blue)

            db.session.commit()

    def tearDown(self):
        with flask_app.app_context():
            db.session.remove()
            db.drop_all()

    def test_blue_domain_detection(self):
        with flask_app.app_context():
            # Clear cache
            import app.utils
            app.utils._BLUE_DOMAINS_CACHE = None

            # Html with link to blue domain
            html = '<html><body><img src="http://internal.com/logo.png"></body></html>'

            result = scan_page_content(html)
            self.assertIn('internal.com', result['blue_links'])

            # Html with no link
            html2 = '<html><body><img src="http://google.com/logo.png"></body></html>'
            result2 = scan_page_content(html2)
            self.assertEqual(len(result2['blue_links']), 0)

    def test_correlation_logic(self):
        with flask_app.app_context():
            # Create Source Domain
            source = PhishingDomain(
                domain_name='source.com',
                ip_address='1.2.3.4',
                asn_number='12345',
                favicon_mmh3='hash123',
                jarm_hash='jarm123',
                html_artifacts=json.dumps({'scripts': ['a.js', 'b.js'], 'stylesheets': []})
            )
            db.session.add(source)
            db.session.commit() # Get ID

            # Create Match Domain (High Score)
            match1 = PhishingDomain(
                domain_name='match1.com',
                ip_address='1.2.3.4', # Match (+20)
                favicon_mmh3='hash123', # Match (+50)
                # Overlap logic: Intersection {a.js}, Union {a.js, b.js, c.js} -> 1/3 = 33% < 50%. No score.
                html_artifacts=json.dumps({'scripts': ['a.js', 'c.js'], 'stylesheets': []})
            )
            db.session.add(match1)

            # Create Partial Match Domain
            match2 = PhishingDomain(
                domain_name='match2.com',
                jarm_hash='jarm123' # Match (+30)
            )
            db.session.add(match2)

            # Create No Match
            nomatch = PhishingDomain(domain_name='nomatch.com', ip_address='9.9.9.9')
            db.session.add(nomatch)

            db.session.commit()

            results = find_related_sites(source.id)

            # Expect match1 (score 70) and match2 (score 30). nomatch (0) excluded.
            # match1 score: IP(20) + Favicon(50) = 70.

            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]['domain'].domain_name, 'match1.com')
            self.assertEqual(results[0]['score'], 70)
            self.assertEqual(results[1]['domain'].domain_name, 'match2.com')
            self.assertEqual(results[1]['score'], 30)

if __name__ == '__main__':
    unittest.main()
