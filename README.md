# Phishing Domain Tracker

A web application to track and monitor phishing domains targeting Travelport.

## Features

- **Domain Tracking**: Store domain name, registration status, date entered, and more.
- **Enrichment**: Automatic enrichment using WhoisXML and Urlscan.io.
- **Monitoring**: Track active status, login pages, and screenshots.
- **Remediation Tracking**: Log actions taken and remediation dates.
- **Ad-hoc Updates**: Refresh data for specific domains on demand.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set environment variables (Optional but recommended for enrichment):
   ```bash
   export WHOISXML_API_KEY="your_key"
   export URLSCAN_API_KEY="your_key"
   ```

3. Run the application:
   ```bash
   python -m app.app
   ```
   Or if in the root directory and after setting PYTHONPATH:
   ```bash
   export PYTHONPATH=$PYTHONPATH:.
   python app/app.py
   ```

4. Access the dashboard at `http://localhost:5000`.

## API Integrations

- **WhoisXML API**: Used for fetching Whois data (registrar, registration status).
- **Urlscan.io**: Used for scanning the URL to get screenshots and detect login pages/activity.
