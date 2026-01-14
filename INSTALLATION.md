# Installation & Deployment

## Prerequisites
- Python 3.8+
- SQLite (default) or other SQLAlchemy-supported database.

## Setup
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set environment variables:
   - `FLASK_APP`: `app.app`
   - `SECRET_KEY`: A strong random string.
   - `DATABASE_URI`: (Optional) Database connection string. Defaults to `sqlite:///domains.db`.
   - `WHOISXML_API_KEY`: (Optional) API key for WhoisXML domain enrichment.
   - `URLSCAN_API_KEY`: (Optional) API key for Urlscan.io enrichment.
   - `PHISHTANK_API_KEY`: (Optional) API key for PhishTank integration.
   - `URLHAUS_API_KEY`: (Optional) API key for URLhaus submission.
   - `GOOGLE_WEBRISK_KEY`: (Optional) API key for Google Web Risk.
   - `GOOGLE_PROJECT_ID`: (Optional) Google Cloud Project ID for Web Risk submission.

## Database Initialization
Run the following commands to set up the database:
```bash
flask db upgrade
```

## Creating Admin User
The application does not create a default user automatically on startup for security reasons, but you can seed it using the flask shell or custom script.
*Example:*
```bash
export FLASK_APP=app/app.py
flask shell
>>> from app.extensions import db, bcrypt
>>> from app.models import User
>>> hashed = bcrypt.generate_password_hash('admin').decode('utf-8')
>>> u = User(username='admin', password_hash=hashed, password_expired=True)
>>> db.session.add(u)
>>> db.session.commit()
```
*(Note: I have already performed this step in the current environment).*

## Running the Server
```bash
flask run --host=0.0.0.0
```

## Security Notes
- Ensure `FLASK_ENV` is set to `production` in a live environment to enable secure cookie settings (`Secure` flag).
- The application uses `ProxyFix` to handle `X-Forwarded-*` headers from Nginx. Ensure your Nginx configuration passes these headers correctly.
