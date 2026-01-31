import time
import sys
import os
import threading
from unittest.mock import MagicMock, patch
import requests

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from app.app import app, db
from app.models import PhishingDomain
from app.scheduler import check_purple_domains

# Mock response object
class MockResponse:
    def __init__(self, status_code=404, text="Not Found"):
        self.status_code = status_code
        self.text = text
        self.url = "http://example.com"

def mock_get_slow(self, url, timeout=None, verify=None):
    # Simulate network latency
    time.sleep(0.1)
    return MockResponse(404)

def benchmark():
    # Setup App Context
    app.config['TESTING'] = True
    # Use file-based DB for thread sharing compatibility
    db_path = "benchmark.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.abspath(db_path)}'
    app.config['WTF_CSRF_ENABLED'] = False

    with app.app_context():
        db.drop_all()
        db.create_all()

        # Seed Data
        num_domains = 20
        print(f"Seeding {num_domains} domains with 'Takedown Requested'...")

        domains = []
        for i in range(num_domains):
            d = PhishingDomain(
                domain_name=f"purple-test-{i}.com",
                manual_status='Takedown Requested',
                is_active=True
            )
            domains.append(d)

        db.session.bulk_save_objects(domains)
        db.session.commit()

        print("Seeding complete.")

        # Patch requests.Session.get because the code now creates local sessions
        with patch('requests.Session.get', autospec=True, side_effect=mock_get_slow):
            print("Starting benchmark (this may take a few seconds)...")
            start_time = time.time()
            check_purple_domains(app)
            end_time = time.time()

        duration = end_time - start_time

        print(f"\n--- Benchmark Results ---")
        print(f"Total Time: {duration:.4f} seconds")
        print(f"Domains Processed: {num_domains}")
        print(f"Avg Time per Domain: {duration/num_domains:.4f} seconds")
        print(f"-------------------------")

    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)

if __name__ == "__main__":
    benchmark()
