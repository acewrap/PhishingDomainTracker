import re
import email
from email import policy
from email.parser import BytesParser
import extract_msg
import logging

logger = logging.getLogger(__name__)

def defang(text):
    if not text:
        return ""
    text = text.replace("http", "hXXp")
    text = text.replace(".", "[.]")
    text = text.replace("@", "[at]")
    return text

def extract_indicators(text):
    indicators = {
        'urls': [],
        'ips': [],
        'domains': [],
        'emails': []
    }

    if not text:
        return indicators

    # URL Regex
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    urls = url_pattern.findall(text)
    indicators['urls'] = list(set(urls))

    # IP Regex
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    ips = ip_pattern.findall(text)
    indicators['ips'] = list(set(ips))

    # Email Regex
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    emails = email_pattern.findall(text)
    indicators['emails'] = list(set(emails))

    # Simple Domain extraction from URLs and Emails
    domains = set()
    for url in urls:
        try:
            # removing protocol
            clean = url.replace('https://', '').replace('http://', '').replace('www.', '')
            domain = clean.split('/')[0].split(':')[0]
            if domain:
                domains.add(domain)
        except:
            pass

    for em in emails:
        try:
            domain = em.split('@')[1]
            domains.add(domain)
        except:
            pass

    # Remove IPs from domains
    final_domains = []
    for d in domains:
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d):
             final_domains.append(d)

    indicators['domains'] = list(final_domains)

    return indicators

def parse_email(file_stream, filename):
    """
    Parses an email file (.eml or .msg) and returns extracted data.
    """
    result = {
        'headers': {},
        'body': "",
        'indicators': {}
    }

    try:
        if filename.lower().endswith('.msg'):
            msg = extract_msg.Message(file_stream)
            result['headers'] = dict(msg.header)
            result['body'] = msg.body
            msg.close()
        else:
            # Assume .eml
            msg = BytesParser(policy=policy.default).parse(file_stream)
            result['headers'] = dict(msg.items())

            # Get body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    try:
                        if "attachment" not in content_disposition:
                            if content_type == "text/plain":
                                body += part.get_content()
                            elif content_type == "text/html":
                                # We could strip HTML here, but for now just appending
                                # For better analysis, maybe keep HTML separate?
                                # But requirement says "extract headers, body content".
                                body += part.get_content()
                    except:
                        pass
            else:
                body = msg.get_content()

            result['body'] = body

        # Extract indicators
        result['indicators'] = extract_indicators(result['body'])

        # Defang indicators for safe display in result (optional, but requested for display)
        # However, we probably want to store raw indicators for correlation, and defang only for display.
        # But the Requirement said: "All extracted indicators must be defanged... before being displayed".
        # So we store raw, but maybe we can also store a defanged version or just defang in the template/PDF.
        # I'll keep them raw here.

    except Exception as e:
        logger.error(f"Error parsing email {filename}: {e}")
        raise e

    return result
