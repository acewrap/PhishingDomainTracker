import os
import requests
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WHOISXML_API_KEY = os.environ.get('WHOISXML_API_KEY')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')

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
        
    return domain_obj
