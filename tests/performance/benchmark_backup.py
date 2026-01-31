import time
import sys
import os
import hashlib
from sqlalchemy import event

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from app.app import app
from app.extensions import db, bcrypt
from app.models import User, APIKey
from app.backup_service import generate_backup_data

def benchmark():
    # Setup App Context
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False

    with app.app_context():
        print(f"Using Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
        db.drop_all()
        db.create_all()

        # Seed Data
        num_users = 2000
        print(f"Seeding {num_users} users and API keys...")

        users = []
        api_keys = []

        # Batch insert for speed
        for i in range(num_users):
            user = User(
                username=f'user_{i}',
                password_hash='hash'
            )
            users.append(user)

        db.session.bulk_save_objects(users)
        db.session.commit()

        # Fetch back users to get IDs (bulk_save_objects doesn't update objects with IDs in sqlite easily without return_defaults which is slow)
        # Alternatively, just query them.
        all_users = User.query.all()

        for user in all_users:
            key = APIKey(
                user_id=user.id,
                access_key=f'key_{user.id}',
                secret_hash='hash'
            )
            api_keys.append(key)

        db.session.bulk_save_objects(api_keys)
        db.session.commit()

        print("Seeding complete.")

        # Clear session to ensure we are testing cold-start performance (no identity map cache)
        db.session.expire_all()
        db.session.remove()

        # Query Counter
        query_count = [0]

        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            query_count[0] += 1

        event.listen(db.engine, "before_cursor_execute", before_cursor_execute)

        # Measure
        start_time = time.time()
        data = generate_backup_data()
        end_time = time.time()

        duration = end_time - start_time

        print(f"\n--- Benchmark Results ---")
        print(f"Total Time: {duration:.4f} seconds")
        print(f"Total Queries: {query_count[0]}")
        print(f"-------------------------")

        # Clean up (mostly for correctness, though memory DB disappears)
        event.remove(db.engine, "before_cursor_execute", before_cursor_execute)

if __name__ == "__main__":
    benchmark()
