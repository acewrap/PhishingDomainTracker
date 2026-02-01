import time
import uuid
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from app.app import app, db
from app.models import PhishingDomain
from app.utils import find_related_sites

def benchmark():
    # Use memory DB
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['TESTING'] = True

    with app.app_context():
        db.create_all()

        # 1. Create Source Domain
        source = PhishingDomain(
            domain_name="source-domain.com",
            ip_address="1.2.3.4",
            asn_number="12345",
            favicon_mmh3="123hash",
            jarm_hash="jarmhash123",
            registrar="GoDaddy",
            html_artifacts='{"scripts": ["jquery.js", "malware.js"], "stylesheets": ["style.css"]}'
        )
        db.session.add(source)
        db.session.commit() # Commit to get ID

        # 2. Seed unrelated domains
        print("Seeding database with 10,000 domains...")
        domains = []
        for i in range(9800):
            d = PhishingDomain(
                domain_name=f"unrelated-{i}.com",
                ip_address=f"10.0.{i % 255}.{i // 255}",
                asn_number=str(i),
                favicon_mmh3=str(uuid.uuid4()),
                jarm_hash=str(uuid.uuid4()),
                registrar=f"Registrar-{i}"
            )
            domains.append(d)

        # 3. Seed related domains
        # IP Match
        for i in range(50):
            d = PhishingDomain(
                domain_name=f"ip-match-{i}.com",
                ip_address="1.2.3.4", # Match
                asn_number=str(i),
                favicon_mmh3=str(uuid.uuid4())
            )
            domains.append(d)

        # Favicon Match
        for i in range(50):
            d = PhishingDomain(
                domain_name=f"favicon-match-{i}.com",
                ip_address=f"11.0.{i}.1",
                favicon_mmh3="123hash" # Match
            )
            domains.append(d)

        # JARM Match
        for i in range(50):
            d = PhishingDomain(
                domain_name=f"jarm-match-{i}.com",
                ip_address=f"12.0.{i}.1",
                jarm_hash="jarmhash123" # Match
            )
            domains.append(d)

         # Artifact Match (Script)
        for i in range(50):
            d = PhishingDomain(
                domain_name=f"artifact-match-{i}.com",
                ip_address=f"13.0.{i}.1",
                html_artifacts='{"scripts": ["malware.js", "other.js"], "stylesheets": []}' # Partial Match
            )
            domains.append(d)

        db.session.bulk_save_objects(domains)
        db.session.commit()

        print("Seeding complete. Running benchmark...")

        start_time = time.time()
        related = find_related_sites(source.id)
        end_time = time.time()

        print(f"Time taken: {end_time - start_time:.4f} seconds")
        print(f"Found {len(related)} related sites.")

        # Cleanup
        db.session.remove()
        db.drop_all()

if __name__ == "__main__":
    benchmark()
