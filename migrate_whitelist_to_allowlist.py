from app.app import app
from app.extensions import db
from app.models import PhishingDomain

def run_migration():
    with app.app_context():
        print("Starting migration...")
        domains = PhishingDomain.query.filter_by(manual_status='Whitelisted').all()
        count = len(domains)
        print(f"Found {count} domains with status 'Whitelisted'.")

        for domain in domains:
            domain.manual_status = 'Allowlisted'

        if count > 0:
            db.session.commit()
            print(f"Updated {count} domains to 'Allowlisted'.")
        else:
            print("No changes needed.")
        print("Migration complete.")

if __name__ == '__main__':
    run_migration()
