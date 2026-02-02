import re
import email
from email import policy
from email.parser import BytesParser
import extract_msg
import logging

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
            try:
                msg = extract_msg.Message(file_stream)

                # Headers
                if hasattr(msg, 'headerDict'):
                    result['headers'] = msg.headerDict
                elif msg.header:
                     try:
                         result['headers'] = dict(msg.header)
                     except:
                         result['headers'] = {"Raw-Header": str(msg.header)}

                # Body
                body_content = msg.body
                if not body_content:
                    # Fallback to HTML body if plain text is missing
                    body_content = msg.htmlBody

                # Ensure string
                if isinstance(body_content, bytes):
                    try:
                        body_content = body_content.decode('utf-8', errors='replace')
                    except Exception as e:
                        logger.warning(f"Failed to decode MSG body bytes: {e}")
                        body_content = str(body_content)

                result['body'] = body_content if body_content else ""

                msg.close()
            except Exception as e:
                logger.error(f"Error extracting MSG content: {e}")
                # Don't re-raise immediately, try to return what we have?
                # But if msg creation failed, we have nothing.
                raise e

        else:
            # Assume .eml
            msg = BytesParser(policy=policy.default).parse(file_stream)
            result['headers'] = dict(msg.items())

            # Helper to extract text from a part
            def get_part_text(part):
                try:
                    # Try default extraction
                    content = part.get_content()
                    return content
                except Exception as e:
                    logger.warning(f"Error getting content from part: {e}")
                    # Fallback: manually decode payload
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            # Try common encodings
                            for encoding in ['utf-8', 'latin-1', 'windows-1252']:
                                try:
                                    return payload.decode(encoding)
                                except:
                                    continue
                            # Last resort: replace errors
                            return payload.decode('utf-8', errors='replace')
                    except Exception as e2:
                        logger.error(f"Failed to extract payload: {e2}")
                return ""

            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    # Check disposition
                    content_disposition = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disposition:
                        continue

                    content_type = part.get_content_type()
                    if content_type in ["text/plain", "text/html"]:
                        text = get_part_text(part)
                        if text:
                            body_parts.append(text)
            else:
                # Single part
                text = get_part_text(msg)
                if text:
                    body_parts.append(text)

            result['body'] = "\n".join(body_parts)

        # Extract indicators
        if result['body']:
            result['indicators'] = extract_indicators(result['body'])
        else:
            logger.warning(f"No body content extracted for {filename}")

    except Exception as e:
        logger.error(f"Error parsing email {filename}: {e}", exc_info=True)
        raise e

    return result
