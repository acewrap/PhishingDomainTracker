import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from logging.handlers import TimedRotatingFileHandler
import urllib3
from datetime import datetime
from bs4 import BeautifulSoup
import re
import dns.resolver
from app.cache import get_compiled_regex
from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user
import socket
import json
from urllib.parse import urljoin

# Setup logging
logging.basicConfig(level=logging.INFO)
# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

# Setup syslog logger
def setup_syslog_logger():
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    sys_logger = logging.getLogger('syslog_logger')
    sys_logger.setLevel(logging.INFO)

    # Check if handler already exists to avoid duplicates
    if not sys_logger.handlers:
        handler = TimedRotatingFileHandler(
            os.path.join(log_dir, 'syslog.log'),
            when='d',
            interval=1,
            backupCount=14
        )
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        sys_logger.addHandler(handler)

    return sys_logger

syslog_logger = setup_syslog_logger()

def log_security_event(event_name, user_id, ip_address, severity='info', domain_name=None, **kwargs):
    """
    Logs a security event in Syslog format with structured JSON data.

    Format: <PRI>1 TIMESTAMP HOSTNAME APPNAME PID - - JSON_MESSAGE
    """
    severity_map = {
        'emergency': 0, 'alert': 1, 'critical': 2, 'error': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
    }

    sev_code = severity_map.get(severity.lower(), 6)
    facility = 1 # User
    priority = (facility * 8) + sev_code

    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    hostname = socket.gethostname()
    app_name = 'PhishingDomainTracker'
    pid = os.getpid()

    # Construct structured data
    log_data = {
        'User': user_id,
        'IP Address': ip_address,
        'Phishing Domain': domain_name if domain_name else "N/A",
        'Action Taken': event_name,
        'timestamp_utc': timestamp
    }
    log_data.update(kwargs)

    # Message part is the JSON string
    message = json.dumps(log_data)

    # Construct Syslog line
    syslog_line = f"<{priority}>1 {timestamp} {hostname} {app_name} {pid} - - {message}"

    syslog_logger.info(syslog_line)

def log_domain_event(domain_name, old_status, new_status, reason):
    """
    Legacy wrapper for domain status changes to use new logging system.
    """
    log_security_event(
        event_name="Domain Status Change",
        user_id="automated",
        ip_address="127.0.0.1",
        severity="info",
        domain_name=domain_name,
        old_status=old_status,
        new_status=new_status,
        reason=reason
    )
    # Also log to main app logger for debugging
    logger.info(f"Domain Change: {domain_name} {old_status}->{new_status} ({reason})")

# Configure Requests Session with Retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
http = requests.Session()
http.mount("https://", adapter)
http.mount("http://", adapter)
# Set User-Agent to mimic a browser to avoid being blocked
http.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
})

WHOISXML_API_KEY = os.environ.get('WHOISXML_API_KEY')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY')
URLHAUS_API_KEY = os.environ.get('URLHAUS_API_KEY')
GOOGLE_WEBRISK_KEY = os.environ.get('GOOGLE_WEBRISK_KEY')
GOOGLE_PROJECT_ID = os.environ.get('GOOGLE_PROJECT_ID')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

# Global cache for threat terms
_THREAT_TERMS_CACHE = None
_THREAT_TERMS_CACHE_TIMESTAMP = 0
_CACHE_TTL = 300  # 5 minutes

def get_threat_terms():
    global _THREAT_TERMS_CACHE, _THREAT_TERMS_CACHE_TIMESTAMP
    import time
    from app.models import ThreatTerm

    now = time.time()
    if _THREAT_TERMS_CACHE is not None and (now - _THREAT_TERMS_CACHE_TIMESTAMP < _CACHE_TTL):
        return _THREAT_TERMS_CACHE

    try:
        terms = [t.term for t in ThreatTerm.query.all()]
        _THREAT_TERMS_CACHE = terms
        _THREAT_TERMS_CACHE_TIMESTAMP = now
        return terms
    except Exception as e:
        logger.warning(f"Error fetching ThreatTerms: {e}")
        # Return cached terms if available even if stale
        if _THREAT_TERMS_CACHE is not None:
             return _THREAT_TERMS_CACHE
        return []

# Global cache for blue domains
_BLUE_DOMAINS_CACHE = None
_BLUE_DOMAINS_CACHE_TIMESTAMP = 0

FOR_SALE_KEYWORDS = [
    "domain is for sale",
    "domain available for sale",
    "buy this domain",
    "inquire about this domain",
    "parked by",
    "godaddy_parked",
    "sedoparking",
    "dan.com",
    "huge domains",
    "domainagents",
    "this domain name is registered"
]

def get_blue_domains():
    global _BLUE_DOMAINS_CACHE, _BLUE_DOMAINS_CACHE_TIMESTAMP
    import time
    from app.models import PhishingDomain

    now = time.time()
    if _BLUE_DOMAINS_CACHE is not None and (now - _BLUE_DOMAINS_CACHE_TIMESTAMP < _CACHE_TTL):
        return _BLUE_DOMAINS_CACHE

    try:
        domains = [d.domain_name for d in PhishingDomain.query.filter_by(manual_status='Internal/Pentest').all()]
        _BLUE_DOMAINS_CACHE = domains
        _BLUE_DOMAINS_CACHE_TIMESTAMP = now
        return domains
    except Exception as e:
        logger.warning(f"Error fetching Blue Domains: {e}")
        if _BLUE_DOMAINS_CACHE is not None:
             return _BLUE_DOMAINS_CACHE
        return []

def scan_page_content(html_content, base_url=None):
    """
    Analyzes the HTML content to check for login page indicators, blue domain links, artifacts, and 'For Sale' status.
    Returns a dict: {'is_login': bool, 'blue_links': list, 'scripts': list, 'stylesheets': list, 'favicon_url': str, 'is_for_sale': bool}
    """
    result = {'is_login': False, 'blue_links': [], 'scripts': [], 'stylesheets': [], 'favicon_url': None, 'is_for_sale': False}
    try:
        soup = BeautifulSoup(html_content, 'html.parser')

        # --- Artifact Extraction ---
        # Scripts
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                filename = src.split('/')[-1].split('?')[0]
                if filename and filename not in result['scripts']:
                    result['scripts'].append(filename)

        # CSS
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link.get('href')
            if href:
                filename = href.split('/')[-1].split('?')[0]
                if filename and filename not in result['stylesheets']:
                    result['stylesheets'].append(filename)

        # Favicon
        icon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower(), href=True)
        if icon_link:
            result['favicon_url'] = icon_link.get('href')

        # --- Blue Domain Check ---
        blue_domains = get_blue_domains()
        if blue_domains:
            # Check img src
            for img in soup.find_all('img', src=True):
                src = img.get('src')
                if not src: continue
                for bd in blue_domains:
                    if bd in src: # Simple substring match
                        if bd not in result['blue_links']:
                            result['blue_links'].append(bd)
                        logger.info(f"Found Blue Domain link: {bd} in {src}")

        # --- Login Page Check ---
        # Check for <input type="password"> case-insensitive
        inputs = soup.find_all('input')
        for inp in inputs:
            if inp.get('type', '').lower() == 'password':
                logger.info("Found password input field.")
                result['is_login'] = True
                break

        # Check for 'For Sale' keywords
        text_content_lower = soup.get_text().lower()
        html_content_lower = html_content.lower()

        for keyword in FOR_SALE_KEYWORDS:
            if keyword in text_content_lower or keyword in html_content_lower:
                logger.info(f"Found 'For Sale' keyword: {keyword}")
                result['is_for_sale'] = True
                break

        if not result['is_login']:
            # Check for specific keywords (case-insensitive)
            text_content = soup.get_text()
            keywords = ["uAPI", "password", "username", "PCC", "HAP", "host access profile"]

            # Add dynamic threat terms
            keywords.extend(get_threat_terms())

            # Helper to check keywords against text
            def check_keywords(text, source_name="text"):
                for keyword in keywords:
                    compiled_regex = get_compiled_regex(keyword)
                    if compiled_regex.search(text):
                        logger.info(f"Found keyword in {source_name}: {keyword}")
                        return True
                return False

            # 1. Check visible text
            if check_keywords(text_content, "visible text"):
                result['is_login'] = True
            # 2. Check raw HTML (for hidden fields, attributes, inline scripts)
            elif check_keywords(html_content, "raw HTML"):
                result['is_login'] = True
            # 3. Fetch and check external scripts
            elif base_url:
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    script_src = script.get('src')
                    if not script_src:
                        continue

                    script_url = urljoin(base_url, script_src)
                    try:
                        # logger.info(f"Fetching external script: {script_url}")
                        # Use a short timeout for scripts
                        resp = http.get(script_url, timeout=5, verify=False)
                        if resp.status_code == 200:
                            if check_keywords(resp.text, f"external script {script_url}"):
                                result['is_login'] = True
                                break
                    except Exception as e:
                        logger.warning(f"Failed to fetch/analyze script {script_url}: {e}")

        return result
    except Exception as e:
        logger.error(f"Error parsing HTML content: {e}")
        return result

def analyze_page_content(html_content, base_url=None):
    """
    Legacy wrapper. Returns True if is_login is True.
    """
    res = scan_page_content(html_content, base_url)
    return res['is_login']

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # logger.info(f"Checking admin access for user: {current_user}")
        if not current_user.is_authenticated or (not current_user.is_admin and current_user.username != 'admin'):

            # Log denied access
            user_id = current_user.username if current_user.is_authenticated else 'anonymous'
            # IP address - simple check, might need request object if available
            from flask import request
            ip = request.remote_addr if request else 'unknown'
            endpoint = request.endpoint if request else 'unknown'

            log_security_event(
                event_name="Unauthorized Admin Access Attempt",
                user_id=user_id,
                ip_address=ip,
                severity="warning",
                endpoint=endpoint
            )

            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def fetch_whois_data(domain_name):
    """
    Fetches raw Whois data from WhoisXML API.
    Returns the JSON dict or None.
    """
    if not WHOISXML_API_KEY:
        logger.warning("WHOISXML_API_KEY not set. Skipping Whois fetch.")
        return None

    try:
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            'apiKey': WHOISXML_API_KEY,
            'domainName': domain_name,
            'outputFormat': 'JSON',
            'ignoreRawTexts': 1
        }
        response = http.get(url, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"WhoisXML API returned {response.status_code}: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Error calling WhoisXML API: {e}")
        return None

def check_mx_record(domain_name):
    """
    Checks if the domain has any MX records.
    Returns a list of MX record strings if found, empty list otherwise.
    """
    records = []
    try:
        answers = dns.resolver.resolve(domain_name, 'MX')
        if answers:
            logger.info(f"MX records found for {domain_name}")
            for rdata in answers:
                records.append(rdata.to_text())
            records.sort()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        pass
    except Exception as e:
        logger.warning(f"Error checking MX records for {domain_name}: {e}")

    return records

def fetch_and_check_domain(domain_name):
    """
    Fetches the domain content (trying https then http) and checks for login indicators and blue links.
    Returns scan result dict or None if fetch failed.
    """
    protocols = ['https://', 'http://']

    for protocol in protocols:
        url = f"{protocol}{domain_name}"
        try:
            logger.info(f"Fetching {url}...")
            # verify=False to handle self-signed certs potentially
            response = http.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                return scan_page_content(response.text, base_url=response.url)
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            continue

    return None

def enrich_domain(domain_obj):
    """
    Enriches the domain object with data from external APIs.
    Updates the domain_obj in place.
    """
    # Sanitize domain name
    if domain_obj.domain_name:
        domain_obj.domain_name = domain_obj.domain_name.strip()

    logger.info(f"Enriching domain: {domain_obj.domain_name}")
    
    # automated/manual context logic?
    # For now we don't know who called this function easily without passing it down.
    # We can rely on the caller to log the "Enrichment Triggered" event,
    # and here we log the specific API calls as requested.
    # Requirement: "Log whenever the tool calls external APIs... Capture userid (or automated...)"
    # Since this function doesn't take a user_id, we might need to inspect Flask global 'current_user' if available.

    user_id = 'automated'
    try:
        if current_user and current_user.is_authenticated:
            user_id = current_user.username
    except:
        pass # outside request context

    # 1. WhoisXML API
    if WHOISXML_API_KEY:
        log_security_event('External API Call', user_id, 'system', 'info', domain_name=domain_obj.domain_name, service='WhoisXML', api_key_name='WHOISXML_API_KEY')
        data = fetch_whois_data(domain_obj.domain_name)
        if data:
            whois_record = data.get('WhoisRecord', {})

            # Update registrar
            if 'registrarName' in whois_record:
                    domain_obj.registrar = whois_record.get('registrarName')

            # Update registration status (simplistic check for now)
            # In reality, might need to parse dates or status codes
            if whois_record.get('parseCode') == 0:
                    domain_obj.registration_status = "Registered"
            else:
                    domain_obj.registration_status = "Unknown/Available"

            # Extract and parse registration date
            created_date_str = whois_record.get('createdDate')
            if not created_date_str:
                registry_data = whois_record.get('registryData')
                if registry_data:
                    created_date_str = registry_data.get('createdDate')

            if created_date_str:
                try:
                    # WhoisXML often returns dates like "2018-06-17 11:23:51.000 UTC" or ISO format
                    # We try to parse the first part if it looks like YYYY-MM-DD
                    # or use datetime.fromisoformat if applicable (Python 3.7+)

                    # Simple parsing strategy:
                    # 1. Try to take the first 19 chars if it's "YYYY-MM-DD HH:MM:SS"
                    # 2. Handle 'T' separator

                    # Remove ' UTC' or other timezones for simplicity if present at the end
                    clean_date_str = created_date_str.replace(' UTC', '').replace('Z', '')

                    # Attempt to handle potential milliseconds .000
                    if '.' in clean_date_str:
                        clean_date_str = clean_date_str.split('.')[0]

                    # Replace T with space
                    clean_date_str = clean_date_str.replace('T', ' ')

                    domain_obj.registration_date = datetime.strptime(clean_date_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    try:
                        # Fallback: try just YYYY-MM-DD
                        domain_obj.registration_date = datetime.strptime(clean_date_str.split(' ')[0], '%Y-%m-%d')
                    except ValueError:
                            logger.warning(f"Could not parse createdDate: {created_date_str}")
                            domain_obj.registration_date = None
            else:
                domain_obj.registration_date = None
    else:
        logger.warning("WHOISXML_API_KEY not set. Skipping Whois enrichment.")

    # 2. Urlscan.io API
    if URLSCAN_API_KEY:
        log_security_event('External API Call', user_id, 'system', 'info', domain_name=domain_obj.domain_name, service='Urlscan.io', api_key_name='URLSCAN_API_KEY')
        try:
            # We want to scan the domain
            headers = {
                'API-Key': URLSCAN_API_KEY,
                'Content-Type': 'application/json'
            }
            data = {
                'url': domain_obj.domain_name,
                'public': 'on'
            }
            
            # Submit scan
            scan_url = "https://urlscan.io/api/v1/scan/"
            response = http.post(scan_url, headers=headers, json=data, timeout=10)
            
            if response.status_code == 200:
                scan_data = response.json()
                uuid = scan_data.get('uuid')
                domain_obj.urlscan_uuid = uuid
                domain_obj.screenshot_link = scan_data.get('result')
                domain_obj.urlscan_status = 'pending'
                domain_obj.last_urlscan_date = datetime.utcnow()
                
                logger.info(f"Urlscan submitted for {domain_obj.domain_name}, UUID: {uuid}")
                
            elif response.status_code == 400:
                 # Often means domain didn't resolve or invalid
                 logger.warning(f"Urlscan returned 400: {response.text}")
            else:
                logger.error(f"Urlscan API returned {response.status_code}")

        except Exception as e:
             logger.error(f"Error calling Urlscan API: {e}")
    else:
        logger.warning("URLSCAN_API_KEY not set. Skipping Urlscan enrichment.")
        
    # 3. Check for login page indicators and blue links
    scan_result = fetch_and_check_domain(domain_obj.domain_name)
    if scan_result:
        # If we successfully fetched the domain, mark it as active
        domain_obj.is_active = True

        if scan_result.get('is_login'):
            logger.info(f"Login page detected for {domain_obj.domain_name}")
            domain_obj.has_login_page = True
        else:
            logger.info(f"No login page detected for {domain_obj.domain_name}")
            domain_obj.has_login_page = False

        # Check for Brown/For Sale status
        if scan_result.get('is_for_sale'):
             # Only move if current status allows (e.g., Yellow/Default)
             if domain_obj.threat_status in ['Yellow', 'Orange']:
                  domain_obj.manual_status = 'Brown'
                  logger.info(f"Domain {domain_obj.domain_name} detected as 'For Sale'. Moving to Brown.")

                  if WHOISXML_API_KEY:
                       whois_data = fetch_whois_data(domain_obj.domain_name)
                       if whois_data:
                            # Store relevant snapshot
                            whois_record = whois_data.get('WhoisRecord', {})
                            snapshot = {
                                'registrant': whois_record.get('registrant', {}),
                                'administrativeContact': whois_record.get('administrativeContact', {}),
                                'technicalContact': whois_record.get('technicalContact', {}),
                                'registrarName': whois_record.get('registrarName'),
                                'createdDate': whois_record.get('createdDate')
                            }
                            domain_obj.whois_snapshot = json.dumps(snapshot)

                  ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                  new_note = f"[{ts}] Status changed to Brown (For Sale) based on page content."
                  if domain_obj.action_taken:
                      domain_obj.action_taken += f"\n{new_note}"
                  else:
                      domain_obj.action_taken = new_note

        # Check Blue Links
        if scan_result.get('blue_links'):
            logger.warning(f"Blue Domain links found: {scan_result['blue_links']}")
            domain_obj.manual_status = 'Confirmed Phish'

            note = f"Linked images to Blue domains: {', '.join(scan_result['blue_links'])}"
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            new_note = f"[{ts}] {note}"
            if domain_obj.action_taken:
                domain_obj.action_taken += f"\n{new_note}"
            else:
                domain_obj.action_taken = new_note

        # Artifacts
        artifacts = {
            'scripts': scan_result.get('scripts', []),
            'stylesheets': scan_result.get('stylesheets', [])
        }
        domain_obj.html_artifacts = json.dumps(artifacts)

        # Favicon Hashing
        favicon_url = scan_result.get('favicon_url')
        if not favicon_url:
            favicon_url = f"http://{domain_obj.domain_name}/favicon.ico" # Fallback
        elif not favicon_url.startswith('http'):
             # Handle relative URL
             favicon_url = urljoin(f"http://{domain_obj.domain_name}", favicon_url)

        try:
             logger.info(f"Fetching favicon: {favicon_url}")
             resp = http.get(favicon_url, timeout=5, verify=False)
             if resp.status_code == 200:
                 import mmh3
                 import codecs
                 # Shodan style: base64 encoded content with newlines
                 b64_content = codecs.encode(resp.content, "base64")
                 favicon_hash = mmh3.hash(b64_content)
                 domain_obj.favicon_mmh3 = str(favicon_hash)
                 logger.info(f"Favicon Hash: {favicon_hash}")
        except Exception as e:
             logger.warning(f"Favicon fetch/hash failed: {e}")

    else:
        # Fetch failed
        logger.info(f"Could not fetch {domain_obj.domain_name} to check for login/blue links")
        domain_obj.is_active = False
        domain_obj.has_login_page = False
        if not domain_obj.date_remediated:
             domain_obj.date_remediated = datetime.utcnow()

    # Resolve IP if missing (needed for ASN)
    if not domain_obj.ip_address:
        try:
            domain_obj.ip_address = socket.gethostbyname(domain_obj.domain_name)
        except Exception:
            pass

    # ASN Lookup
    if domain_obj.ip_address:
         try:
             from ipwhois import IPWhois
             obj = IPWhois(domain_obj.ip_address)
             res = obj.lookup_rdap(depth=1)
             domain_obj.asn_number = str(res.get('asn'))
             domain_obj.asn_org = res.get('asn_description') or res.get('asn_registry')
         except Exception as e:
             logger.warning(f"ASN lookup failed: {e}")

    # JARM Fingerprinting
    try:
        from jarm.scanner.scanner import Scanner
        # Scanner.scan is a sync wrapper around async
        logger.info(f"Running JARM scan for {domain_obj.domain_name}")
        jarm_hash, _, _ = Scanner.scan(domain_obj.domain_name, 443)
        if jarm_hash and "00000000000000000000" not in jarm_hash: # Check for complete failure/empty
             domain_obj.jarm_hash = jarm_hash
        else:
             logger.info("JARM scan returned empty/failure hash.")
    except Exception as e:
         logger.warning(f"JARM scan failed: {e}")

    # 4. Check for MX records
    mx_records = check_mx_record(domain_obj.domain_name)
    if mx_records:
        domain_obj.has_mx_record = True
        domain_obj.mx_records = "\n".join(mx_records)
    else:
        domain_obj.has_mx_record = False
        domain_obj.mx_records = None

    return domain_obj

def report_to_vendors(domain_obj):
    """
    Reports the domain to security vendors (Google Web Risk, URLhaus, PhishTank).
    Returns a dictionary of results.
    """
    results = {}
    domain_url = domain_obj.domain_name
    # Ensure scheme is present for submission
    if not domain_url.startswith('http'):
        domain_url = f"http://{domain_url}"

    logger.info(f"Reporting domain {domain_url} to vendors...")

    user_id = 'automated'
    try:
        if current_user and current_user.is_authenticated:
            user_id = current_user.username
    except:
        pass

    # 1. Google Web Risk
    if GOOGLE_WEBRISK_KEY and GOOGLE_PROJECT_ID:
        log_security_event('External API Call', user_id, 'system', 'info', domain_name=domain_obj.domain_name, service='Google Web Risk', api_key_name='GOOGLE_WEBRISK_KEY')
        try:
            url = f"https://webrisk.googleapis.com/v1/projects/{GOOGLE_PROJECT_ID}/uris:submit"
            params = {'key': GOOGLE_WEBRISK_KEY}
            data = {"submission": {"uri": domain_url}}
            response = http.post(url, params=params, json=data, timeout=10)
            if response.status_code == 200:
                results['Google Web Risk'] = 'Success'
            else:
                logger.error(f"Google Web Risk error: {response.text}")
                results['Google Web Risk'] = f"Failed ({response.status_code})"
        except Exception as e:
            logger.error(f"Google Web Risk exception: {e}")
            results['Google Web Risk'] = f"Error: {str(e)}"
    else:
        results['Google Web Risk'] = 'Skipped (Missing Config)'

    # 2. URLhaus
    if URLHAUS_API_KEY:
        log_security_event('External API Call', user_id, 'system', 'info', domain_name=domain_obj.domain_name, service='URLhaus', api_key_name='URLHAUS_API_KEY')
        try:
            url = "https://urlhaus.abuse.ch/api/"
            headers = {'Auth-Key': URLHAUS_API_KEY}
            # URLhaus expects 'submission' as a list of objects
            # threat must be 'malware_download' per docs/API constraint
            data = {
                'anonymous': '0',
                'submission': [
                    {
                        'url': domain_url,
                        'threat': 'malware_download'
                    }
                ]
            }
            response = http.post(url, headers=headers, json=data, timeout=10)
            if response.status_code == 200:
                try:
                    resp_json = response.json()
                    # Check for bulk submission response format
                    # Example success: {"query_status": "ok", ...}
                    q_status = resp_json.get('query_status')
                    if q_status == 'ok' or 'submission_results' in resp_json:
                         results['URLhaus'] = 'Success'
                    else:
                         results['URLhaus'] = f"Failed ({q_status or 'Unknown'})"
                except ValueError:
                    results['URLhaus'] = 'Success (Non-JSON response)'
            else:
                logger.error(f"URLhaus error: {response.text}")
                results['URLhaus'] = f"Failed ({response.status_code})"
        except Exception as e:
            logger.error(f"URLhaus exception: {e}")
            results['URLhaus'] = f"Error: {str(e)}"
    else:
        results['URLhaus'] = 'Skipped (Missing Key)'

    # 3. PhishTank
    if PHISHTANK_API_KEY:
        log_security_event('External API Call', user_id, 'system', 'info', domain_name=domain_obj.domain_name, service='PhishTank', api_key_name='PHISHTANK_API_KEY')
        # No public submission API available
        results['PhishTank'] = 'Skipped (No Submission API)'
    else:
        results['PhishTank'] = 'Skipped (Missing Key)'

    # 4. VirusTotal
    if VIRUSTOTAL_API_KEY:
        log_security_event('External API Call', user_id, 'system', 'info', domain_name=domain_obj.domain_name, service='VirusTotal', api_key_name='VIRUSTOTAL_API_KEY')
        try:
             res_vt = submit_vt_url(domain_url)
             if res_vt.get('data'):
                 results['VirusTotal'] = 'Success'
             else:
                 results['VirusTotal'] = f"Failed ({res_vt.get('error', {}).get('message', 'Unknown Error')})"
        except Exception as e:
            logger.error(f"VirusTotal exception: {e}")
            results['VirusTotal'] = f"Error: {str(e)}"
    else:
        results['VirusTotal'] = 'Skipped (Missing Key)'

    return results

def submit_vt_url(url):
    """
    Submits a URL to VirusTotal for scanning.
    """
    if not VIRUSTOTAL_API_KEY:
        return {'error': {'message': 'API Key not configured'}}

    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    data = {"url": url}

    try:
        response = http.post(api_url, headers=headers, data=data, timeout=10)
        return response.json()
    except Exception as e:
        logger.error(f"Error submitting to VT: {e}")
        return {'error': {'message': str(e)}}

def check_vt_reputation(indicator, indicator_type):
    """
    Checks VirusTotal reputation for an indicator (ip, domain, url).
    indicator_type: 'ip', 'domain', 'url'
    Returns dict with stats or None.
    """
    if not VIRUSTOTAL_API_KEY:
        return None

    base_url = "https://www.virustotal.com/api/v3"
    endpoint = ""

    if indicator_type == 'ip':
        endpoint = f"/ip_addresses/{indicator}"
    elif indicator_type == 'domain':
        endpoint = f"/domains/{indicator}"
    elif indicator_type == 'url':
        # URLs are tricky, need base64 identifier without padding
        import base64
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        endpoint = f"/urls/{url_id}"
    else:
        return None

    url = f"{base_url}{endpoint}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = http.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return stats
        elif response.status_code == 404:
            return {'harmless': 0, 'malicious': 0, 'suspicious': 0, 'undetected': 0, 'status': 'Not Found'}
    except Exception as e:
        logger.error(f"Error checking VT reputation for {indicator}: {e}")

    return None

def find_related_sites(domain_id):
    """
    Finds related domains based on shared infrastructure and artifacts.
    Returns a list of dicts: [{'domain': domain_obj, 'score': int, 'pivots': list}]
    """
    from app.models import PhishingDomain
    source = PhishingDomain.query.get(domain_id)
    if not source:
        return []

    related = []
    candidates = PhishingDomain.query.filter(PhishingDomain.id != domain_id).all()

    source_artifacts = {}
    if source.html_artifacts:
        try:
            source_artifacts = json.loads(source.html_artifacts)
        except:
            pass

    source_scripts = set(source_artifacts.get('scripts', []))
    source_css = set(source_artifacts.get('stylesheets', []))

    for candidate in candidates:
        score = 0
        pivots = []

        # IP Match
        if source.ip_address and candidate.ip_address and source.ip_address == candidate.ip_address:
            score += 20
            pivots.append("Same IP")

        # ASN Match
        if source.asn_number and candidate.asn_number and source.asn_number == candidate.asn_number:
            score += 10
            pivots.append(f"Same ASN")

        # Favicon Match
        if source.favicon_mmh3 and candidate.favicon_mmh3 and source.favicon_mmh3 == candidate.favicon_mmh3:
            score += 50
            pivots.append("Same Favicon")

        # JARM Match
        if source.jarm_hash and candidate.jarm_hash and source.jarm_hash == candidate.jarm_hash:
             score += 30
             pivots.append("Same JARM")

        # Registrar Match
        if source.registrar and candidate.registrar and source.registrar == candidate.registrar:
            score += 5
            pivots.append("Same Registrar")

        # Artifact Overlap
        cand_artifacts = {}
        if candidate.html_artifacts:
            try:
                cand_artifacts = json.loads(candidate.html_artifacts)
            except:
                pass

        cand_scripts = set(cand_artifacts.get('scripts', []))
        cand_css = set(cand_artifacts.get('stylesheets', []))

        # Scripts
        if source_scripts and cand_scripts:
            intersection = source_scripts.intersection(cand_scripts)
            union = source_scripts.union(cand_scripts)
            if len(union) > 0:
                overlap_pct = len(intersection) / len(union)
                if overlap_pct > 0.5:
                    score += 20
                    pivots.append(f"Script Overlap ({int(overlap_pct*100)}%)")

        # CSS
        if source_css and cand_css:
            intersection = source_css.intersection(cand_css)
            union = source_css.union(cand_css)
            if len(union) > 0:
                overlap_pct = len(intersection) / len(union)
                if overlap_pct > 0.5:
                    score += 20
                    pivots.append(f"CSS Overlap ({int(overlap_pct*100)}%)")

        if score >= 20:
             related.append({
                 'domain': candidate,
                 'score': score,
                 'pivots': pivots
             })

    related.sort(key=lambda x: x['score'], reverse=True)
    return related

def process_urlscan_result(domain_obj, app):
    """
    Checks if a Urlscan result is ready, downloads screenshot, and enriches domain.
    Returns True if processed, False if still pending or failed.
    """
    if not URLSCAN_API_KEY:
        return False

    if not domain_obj.urlscan_uuid:
        return False

    uuid = domain_obj.urlscan_uuid
    url = f"https://urlscan.io/api/v1/result/{uuid}/"

    try:
        response = http.get(url, timeout=10)
        if response.status_code == 404:
            # Still pending or invalid
            return False

        if response.status_code == 200:
            data = response.json()

            # Check for screenshot URL
            task = data.get('task', {})
            page = data.get('page', {})
            lists = data.get('lists', {})

            # Enrich Domain Data
            if not domain_obj.ip_address and page.get('ip'):
                domain_obj.ip_address = page.get('ip')

            if not domain_obj.asn_number and page.get('asn'):
                 domain_obj.asn_number = str(page.get('asn').replace('AS', ''))

            if not domain_obj.asn_org and page.get('asnname'):
                 domain_obj.asn_org = page.get('asnname')

            # Download Screenshot
            screenshot_url = task.get('screenshotURL')
            if screenshot_url:
                try:
                    # Download image
                    img_resp = http.get(screenshot_url, timeout=20)
                    if img_resp.status_code == 200:
                        filename = f"urlscan_{uuid}.png"
                        static_dir = os.path.join(app.root_path, 'static', 'screenshots')
                        if not os.path.exists(static_dir):
                            os.makedirs(static_dir)

                        filepath = os.path.join(static_dir, filename)
                        with open(filepath, 'wb') as f:
                            f.write(img_resp.content)

                        # Create Screenshot Record
                        from app.models import DomainScreenshot
                        from app.extensions import db

                        # Check if already exists?
                        existing = DomainScreenshot.query.filter_by(urlscan_uuid=uuid).first()
                        if not existing:
                            screenshot = DomainScreenshot(
                                domain_id=domain_obj.id,
                                image_filename=filename,
                                urlscan_uuid=uuid,
                                scan_data=json.dumps(data)
                            )
                            db.session.add(screenshot)
                            logger.info(f"Downloaded screenshot for {domain_obj.domain_name}")

                except Exception as e:
                    logger.error(f"Failed to download screenshot: {e}")

            domain_obj.urlscan_status = 'complete'
            domain_obj.last_urlscan_date = datetime.utcnow()
            return True

    except Exception as e:
        logger.error(f"Error processing urlscan result for {domain_obj.domain_name}: {e}")

    return False

def poll_pending_urlscans(app):
    """
    Polls pending Urlscan submissions.
    """
    from app.models import PhishingDomain
    from app.extensions import db

    with app.app_context():
        # Find domains with pending status or new status (if uuid present)
        pending_domains = PhishingDomain.query.filter(
            PhishingDomain.urlscan_uuid.isnot(None),
            PhishingDomain.urlscan_status.in_(['new', 'pending'])
        ).all()

        count = 0
        for domain in pending_domains:
            if process_urlscan_result(domain, app):
                count += 1
                db.session.commit()

        if count > 0:
            logger.info(f"Processed {count} Urlscan results.")
