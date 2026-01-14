import unittest
from datetime import datetime
from app.models import PhishingDomain

class TestThreatStatus(unittest.TestCase):

    def test_manual_overrides_high_priority(self):
        # Allowlisted -> Green
        d = PhishingDomain(domain_name='safe.com', manual_status='Allowlisted')
        self.assertEqual(d.threat_status, 'Green')

        # Internal/Pentest -> Blue
        d = PhishingDomain(domain_name='pentest.com', manual_status='Internal/Pentest')
        self.assertEqual(d.threat_status, 'Blue')

        # Override Red
        d = PhishingDomain(domain_name='partner-login.com', manual_status='Allowlisted', is_active=True, has_login_page=True)
        self.assertEqual(d.threat_status, 'Green')

    def test_remediated(self):
        # Remediated -> Grey
        d = PhishingDomain(domain_name='dead.com', date_remediated=datetime.utcnow())
        self.assertEqual(d.threat_status, 'Grey')

        # Remediated overrides Purple (Takedown Requested)
        d = PhishingDomain(domain_name='takedown-done.com', manual_status='Takedown Requested', date_remediated=datetime.utcnow())
        self.assertEqual(d.threat_status, 'Grey')

        # But Allowlisted overrides Remediated (if for some reason both set)
        d = PhishingDomain(domain_name='safe-old.com', manual_status='Allowlisted', date_remediated=datetime.utcnow())
        self.assertEqual(d.threat_status, 'Green')

    def test_manual_overrides_action_pending(self):
        # Takedown Requested -> Purple
        d = PhishingDomain(domain_name='taking-down.com', manual_status='Takedown Requested')
        self.assertEqual(d.threat_status, 'Purple')

        # Purple overrides Red
        d = PhishingDomain(domain_name='phish.com', manual_status='Takedown Requested', is_active=True, has_login_page=True)
        self.assertEqual(d.threat_status, 'Purple')

    def test_automated_threats(self):
        # Active + Login -> Red
        d = PhishingDomain(domain_name='evil.com', is_active=True, has_login_page=True)
        self.assertEqual(d.threat_status, 'Red')

        # Active only (no login) -> Yellow (or Orange if MX)
        d = PhishingDomain(domain_name='evil-parked.com', is_active=True, has_login_page=False)
        self.assertEqual(d.threat_status, 'Yellow')

        # MX Record -> Orange
        d = PhishingDomain(domain_name='mailer.com', has_mx_record=True)
        self.assertEqual(d.threat_status, 'Orange')

        # Red overrides Orange
        d = PhishingDomain(domain_name='evil-mailer.com', is_active=True, has_login_page=True, has_mx_record=True)
        self.assertEqual(d.threat_status, 'Red')

    def test_default(self):
        # Default -> Yellow
        d = PhishingDomain(domain_name='new.com')
        self.assertEqual(d.threat_status, 'Yellow')

if __name__ == '__main__':
    unittest.main()
