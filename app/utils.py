import os
import requests
import logging
import urllib3
from datetime import datetime
from bs4 import BeautifulSoup
import re
import dns.resolver
from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

# Setup logging
logging.basicConfig(level=logging.INFO)
# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

WHOISXML_API_KEY = os.environ.get('WHOISXML_API_KEY')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')

def analyze_page_content(html_content):
    """
    Analyzes the HTML content to check for login page indicators.
    Returns True if indicators are found, False otherwise.
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')

        # Check for <input type="password">
        if soup.find('input', {'type': 'password'}):
            logger.info("Found password input field.")
            return True

        # Check for specific keywords (case-insensitive)
        text_content = soup.get_text()
        keywords = ["uAPI", "password", "username", "PCC", "HAP", "host access profile"]

        for keyword in keywords:
            if re.search(r'\b' + re.escape(keyword) + r'\b', text_content, re.IGNORECASE):
                logger.info(f"Found keyword: {keyword}")
                return True

        return False
    except Exception as e:
        logger.error(f"Error parsing HTML content: {e}")
        return False

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # logger.info(f"Checking admin access for user: {current_user}")
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def check_mx_record(domain_name):
    """
    Checks if the domain has any MX records.
    Returns True if MX records are found, False otherwise.
    """
    try:
        answers = dns.resolver.resolve(domain_name, 'MX')
        if answers:
            logger.info(f"MX records found for {domain_name}")
            return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        pass
    except Exception as e:
        logger.warning(f"Error checking MX records for {domain_name}: {e}")

    return False

def fetch_and_check_domain(domain_name):
    """
    Fetches the domain content (trying https then http) and checks for login indicators.
    Returns True if login page detected, False otherwise.
    """
    protocols = ['https://', 'http://']

    for protocol in protocols:
        url = f"{protocol}{domain_name}"
        try:
            logger.info(f"Fetching {url}...")
            response = requests.get(url, timeout=10, verify=False) # verify=False to handle self-signed certs potentially
            if response.status_code == 200:
                if analyze_page_content(response.text):
                    return True
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            continue

    return False

def enrich_domain(domain_obj):
    """
    Enriches the domain object with data from external APIs.
    Updates the domain_obj in place.
    """
    logger.info(f"Enriching domain: {domain_obj.domain_name}")
    
    # 1. WhoisXML API
    if WHOISXML_API_KEY:
        try:
            # Note: This is a placeholder URL and structure. 
            # In a real scenario, check the specific API endpoint and params.
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
            params = {
                'apiKey': WHOISXML_API_KEY,
                'domainName': domain_obj.domain_name,
                'outputFormat': 'JSON'
            }
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
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
                logger.error(f"WhoisXML API returned {response.status_code}")
        except Exception as e:
            logger.error(f"Error calling WhoisXML API: {e}")
    else:
        logger.warning("WHOISXML_API_KEY not set. Skipping Whois enrichment.")

    # 2. Urlscan.io API
    if URLSCAN_API_KEY:
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
            response = requests.post(scan_url, headers=headers, json=data, timeout=10)
            
            if response.status_code == 200:
                scan_data = response.json()
                uuid = scan_data.get('uuid')
                domain_obj.urlscan_uuid = uuid
                
                # We can't get the result immediately. 
                # Ideally, we would need to poll, or just store the UUID and let the user click a link.
                # However, for 'enrichment' we might want some immediate feedback if it was already scanned recently?
                # For now, let's just store the UUID and link to the result page.
                
                domain_obj.screenshot_link = scan_data.get('result') # This is usually the result page URL
                
                # To get the actual screenshot image or status, we'd need to query the result API 
                # using the UUID after some time.
                # For this MVP, we will set the result link.
                
                # Optimistic 'Active' status if scan submission worked
                domain_obj.is_active = True 
                
            elif response.status_code == 400:
                 # Often means domain didn't resolve or invalid
                 logger.warning(f"Urlscan returned 400: {response.text}")
            else:
                logger.error(f"Urlscan API returned {response.status_code}")

        except Exception as e:
             logger.error(f"Error calling Urlscan API: {e}")
    else:
        logger.warning("URLSCAN_API_KEY not set. Skipping Urlscan enrichment.")
        
    # 3. Check for login page indicators
    if fetch_and_check_domain(domain_obj.domain_name):
        logger.info(f"Login page detected for {domain_obj.domain_name}")
        domain_obj.has_login_page = True
    else:
        logger.info(f"No login page detected for {domain_obj.domain_name}")
        domain_obj.has_login_page = False

    # 4. Check for MX records
    if check_mx_record(domain_obj.domain_name):
        domain_obj.has_mx_record = True
    else:
        domain_obj.has_mx_record = False

    return domain_obj
