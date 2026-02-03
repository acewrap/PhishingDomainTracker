import re
import email
from email import policy
from email.parser import BytesParser
import extract_msg
import logging
import json

logger = logging.getLogger(__name__)

# Compile regex patterns once at module level
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
IP_EXACT_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

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
    urls = URL_PATTERN.findall(text)
    indicators['urls'] = list(set(urls))

    # IP Regex
    ips = IP_PATTERN.findall(text)
    indicators['ips'] = list(set(ips))

    # Email Regex
    emails = EMAIL_PATTERN.findall(text)
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
        if not IP_EXACT_PATTERN.match(d):
             final_domains.append(d)

    indicators['domains'] = list(final_domains)

    return indicators

def _parse_msg_headers(msg):
    """
    Robust header extraction for MSG files.
    """
    headers = {}
    try:
        # Try primary header property
        if hasattr(msg, 'header') and msg.header:
            headers = dict(msg.header)

        # Fallback to headerDict
        if not headers and hasattr(msg, 'headerDict') and msg.headerDict:
             headers = dict(msg.headerDict)

        # Fallback to transport headers string (requires parsing)
        if not headers:
            transport_headers = None
            if hasattr(msg, 'transport_headers') and msg.transport_headers:
                transport_headers = msg.transport_headers
            else:
                # Try getting property directly (PR_TRANSPORT_MESSAGE_HEADERS = 0x007D001E)
                # extract_msg uses '007D001E' usually
                try:
                    transport_headers = msg.getProperty('007D001E')
                except:
                    pass

            if transport_headers and isinstance(transport_headers, str):
                # Parse string headers
                parser = BytesParser(policy=policy.default)
                parsed = parser.parsebytes(transport_headers.encode('utf-8'))
                headers = dict(parsed.items())

    except Exception as e:
        logger.warning(f"Error extracting MSG headers: {e}")

    return headers

def _parse_msg_body(msg):
    """
    Robust body extraction for MSG files.
    """
    body = ""
    try:
        # 1. Plain Text Body
        if msg.body:
            body = msg.body

        # 2. HTML Body (fallback or append?)
        # Requirement: "extracting the headers AND body"
        # If plain text is empty or missing, use HTML (converted to text or raw)
        # Using raw HTML is safer for preserving links/indicators
        if not body and msg.htmlBody:
             try:
                 html = msg.htmlBody
                 if isinstance(html, bytes):
                      html = html.decode('utf-8', errors='ignore')
                 body = html
             except Exception:
                 pass

        # 3. RTF Body (rarely needed if HTML exists)
    except Exception as e:
         logger.warning(f"Error extracting MSG body: {e}")

    return body

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
            result['headers'] = _parse_msg_headers(msg)
            result['body'] = _parse_msg_body(msg)
            msg.close()
        else:
            # Assume .eml
            msg = BytesParser(policy=policy.default).parse(file_stream)
            result['headers'] = dict(msg.items())

            # Get body
            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    # Skip container parts
                    if part.is_multipart():
                        continue

                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    try:
                        # Ignore attachments unless inline?
                        # User wants body content.
                        if "attachment" not in content_disposition:
                            payload = part.get_content()
                            if payload:
                                body_parts.append(str(payload))
                    except Exception as e:
                         # Start logging warnings but continue
                         logger.warning(f"Failed to extract part: {e}")
            else:
                try:
                    payload = msg.get_content()
                    if payload:
                        body_parts.append(str(payload))
                except Exception as e:
                    # Fallback to get_payload()
                    try:
                        body_parts.append(str(msg.get_payload(decode=True).decode('utf-8', errors='ignore')))
                    except:
                        pass

            result['body'] = "\n\n".join(body_parts)

        # Extract indicators
        result['indicators'] = extract_indicators(result['body'])

        # Sanitize keys in headers to ensure JSON compatibility (just in case)
        # queue_service dumps to JSON
        # Values are usually strings, but lets ensure
        sanitized_headers = {}
        for k, v in result['headers'].items():
            if isinstance(k, (str, int, float, bool, type(None))):
                sanitized_headers[str(k)] = str(v)
        result['headers'] = sanitized_headers

    except Exception as e:
        logger.error(f"Error parsing email {filename}: {e}")
        raise e

    return result
