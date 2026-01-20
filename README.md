# Phishing Domain Tracker

A secure web application to track and monitor phishing domains targeting your organization.

## Features

- **Domain Tracking**: Store domain name, registration status, date entered, and more.
- **Enrichment**: Automatic enrichment using WhoisXML and Urlscan.io.
- **Monitoring**: Track active status, login pages, and screenshots.
- **Automated Lifecycle**: Background checks for different domain categories (Red, Orange, Yellow, Purple, Grey).
- **Threat Detection**: Detect phishing kits and keywords (e.g., "password", "Company Product") using customizable Threat Terms.
- **Email Analysis**: Ingest and parse .eml/.msg files, extracting indicators and checking them against VirusTotal.
- **Remediation Tracking**: Log actions taken and remediation dates.
- **Reporting**: Report confirmed phishing domains to vendors (Google Web Risk, URLhaus, VirusTotal) with a single click.
- **Infrastructure Correlation**: Automatically identify related phishing domains based on shared infrastructure (IP, ASN, Favicon, JARM) and Email Evidence.
- **User Authentication**: Secure login, password rotation policies, and admin user management.
- **Programmatic API**: Secure API access using API Key & Secret.

![Dashboard](docs/images/dashboard.png)

## Documentation

For detailed instructions, please refer to the following guides:

- **[Installation & Setup](INSTALLATION.md)**: How to install, configure, and run the application.
- **[Administrator Guide](ADMINISTRATOR.md)**: Managing users, system configuration, and threat terms.
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

4. (Optional) Run the Background Worker:
   ```bash
   flask run-worker
   ```

5. Access the dashboard at `http://localhost:8080`.
   *(Default Admin Credentials: `admin` / `admin` - Change immediately upon login)*

## Automated Lifecycle Monitoring

The application includes a background scheduler (APScheduler) that performs automated checks:

*   **Purple (6 Hours)**: Checks 'Takedown Requested' domains. If 404 or content removed, moves to Grey.
*   **Red (24 Hours)**: Checks Active/Login domains. If unreachable, moves to Grey. Updates IP.
*   **Orange (24 Hours)**: Checks MX records. Logs modifications.
*   **Yellow (Weekly)**: Checks Parked/Monitored domains. If 200 OK or content (Login/Threat Terms) detected, moves to Red.
*   **Grey (Monthly)**: Checks Remediated domains. If back to life, moves to Red.

Logs are written to `logs/syslog.log` in a Syslog-compatible KV format, rotated daily.

## Threat Terms Management

Admins can manage a list of "Threat Terms" via the Admin menu. These terms are used during scanning (Yellow/Grey checks and initial enrichment) to detect potential phishing content.

## Infrastructure Correlation

The application employs advanced fingerprinting techniques to detect related infrastructure. When viewing a domain, the "Infrastructure Correlations" section displays other tracked domains that share:

*   **IP Address**: Co-hosting on the same server.
*   **ASN**: Hosting on the same Autonomous System.
*   **Favicon (MMH3 Hash)**: Using the same favicon icon.
*   **JARM Hash**: Identical TLS configuration fingerprints.
*   **HTML Artifacts**: Overlapping scripts or stylesheets.

It also correlates **Email Evidence** (uploaded .eml/.msg files) with monitored domains based on extracted indicators.

![Infrastructure Correlation](docs/images/domain_details.png)

## API Integrations

- **WhoisXML API**: Used for fetching Whois data (registrar, registration status).
- **Urlscan.io**: Used for scanning the URL to get screenshots and detect login pages/activity.
- **Google Web Risk, URLhaus, & VirusTotal**: Integration for reporting active phishing domains and checking reputation.
