# Phishing Domain Tracker

A secure web application to track and monitor phishing domains targeting your organization.

## Features

- **Domain Tracking**: Store domain name, registration status, date entered, and more.
- **Enrichment**: Automatic enrichment using WhoisXML and Urlscan.io.
- **Monitoring**: Track active status, login pages, and screenshots.
- **Remediation Tracking**: Log actions taken and remediation dates.
- **User Authentication**: Secure login, password rotation policies, and admin user management.
- **Programmatic API**: Secure API access using API Key & Secret.

## Documentation

For detailed instructions, please refer to the following guides:

- **[Installation & Setup](INSTALLATION.md)**: How to install, configure, and run the application.
- **[Administrator Guide](ADMINISTRATOR.md)**: Managing users and system configuration.
- **[User Guide](USER.md)**: Using the dashboard and managing your profile/API keys.
- **[API Documentation](API.md)**: How to use the REST API.

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Initialize the database:
   ```bash
   export FLASK_APP=app/app.py
   flask db upgrade
   ```

3. Run the application:
   ```bash
   flask run --host=0.0.0.0 --port=8080
   ```

4. Access the dashboard at `http://localhost:8080`.
   *(Default Admin Credentials: `admin` / `admin` - Change immediately upon login)*

## API Integrations

- **WhoisXML API**: Used for fetching Whois data (registrar, registration status).
- **Urlscan.io**: Used for scanning the URL to get screenshots and detect login pages/activity.
