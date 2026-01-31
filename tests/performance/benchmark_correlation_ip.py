import time
import json
import unittest
from app.app import app, db
from app.models import PhishingDomain, EmailEvidence
from app.correlation_engine import correlate_evidence

class CorrelationBenchmark(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        # Disable logging to avoid noise in benchmark
        import logging
        logging.getLogger('app.correlation_engine').setLevel(logging.WARNING)

        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            self.seed_data()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def seed_data(self):
        print("Seeding database...")
        domains = []
        # Create 10,000 domains
        # We want to ensure we have matches.
        # Let's say we search for IPs '1.2.3.0' to '1.2.3.99'

        for i in range(10000):
            # Assign IPs.
            # 1000 domains will have '1.2.3.X' (where X is 0-99)
            # This means each IP in our search list (of 100) will match about 10 domains.
            ip = None
            if i < 1000:
                ip = f"1.2.3.{i % 100}"
            else:
                ip = f"10.0.{i // 255}.{i % 255}"

            domains.append(PhishingDomain(
                domain_name=f"domain_{i}.com",
                ip_address=ip
            ))

        db.session.bulk_save_objects(domains)
        db.session.commit()
        print("Seeded 10,000 domains.")

    def test_benchmark_ip_correlation(self):
        with app.app_context():
            # Create Evidence with 100 IPs
            # All 100 IPs (1.2.3.0 - 1.2.3.99) are present in DB.
            # We also add some non-matching IPs to the search list.

            search_ips = [f"1.2.3.{i}" for i in range(100)]
            # Add 100 non-matching IPs
            search_ips.extend([f"9.9.9.{i}" for i in range(100)])

            evidence = EmailEvidence(
                filename='bench.eml',
                extracted_indicators=json.dumps({
                    'domains': [],
                    'ips': search_ips,
                    'urls': []
                })
            )
            db.session.add(evidence)
            db.session.commit()

            print(f"Starting benchmark: Correlation of {len(search_ips)} IPs against 10,000 domains...")
            start_time = time.time()
            count = correlate_evidence(evidence.id)
            end_time = time.time()

            duration = end_time - start_time
            print(f"BENCHMARK_RESULT: {duration:.4f} seconds")
            print(f"Matches found: {count}")

if __name__ == '__main__':
    unittest.main()
