import re
import email
from email import policy
from email.parser import BytesParser, HeaderParser
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

                # --- Headers Extraction ---
                headers = {}

                # Strategy 1: msg.headerDict (Parsed dictionary)
                if hasattr(msg, 'headerDict') and msg.headerDict:
                    headers = msg.headerDict
                    logger.info(f"Extracted headers using headerDict for {filename}")

                # Strategy 2: msg.header (Raw string or object)
                if not headers and hasattr(msg, 'header') and msg.header:
                    if isinstance(msg.header, dict):
                        headers = msg.header
                        logger.info(f"Extracted headers using msg.header (dict) for {filename}")
                    else:
                        # Assume string (raw headers)
                        try:
                            # Use email library to parse raw header string
                            raw_headers = str(msg.header)
                            parsed_headers = HeaderParser().parsestr(raw_headers)
                            headers = dict(parsed_headers.items())
                            logger.info(f"Extracted headers by parsing msg.header string for {filename}")
                        except Exception as e:
                            logger.warning(f"Failed to parse raw msg.header: {e}")
                            headers = {"Raw-Header": str(msg.header)[:1000]} # Truncate for safety

                # Strategy 3: Explicit transport_headers check (common fallback)
                if not headers:
                     # Sometimes 'transport_headers' is a property or key in props
                     # This is a best-effort check for specific extract-msg quirks
                     try:
                         # 0x007D is PR_TRANSPORT_MESSAGE_HEADERS
                         transport_headers = msg.getProps().get('007D001F') or msg.getProps().get('007D001E')
                         if transport_headers:
                             parsed_headers = HeaderParser().parsestr(transport_headers.value)
                             headers = dict(parsed_headers.items())
                             logger.info(f"Extracted headers from PR_TRANSPORT_MESSAGE_HEADERS for {filename}")
                     except Exception as e:
                         logger.debug(f"Failed to extract via properties: {e}")

                result['headers'] = headers
                if not headers:
                    logger.warning(f"No headers found for MSG file: {filename}")

                # --- Body Extraction ---
                body_content = msg.body
                source = "body"

                if not body_content:
                    body_content = msg.htmlBody
                    source = "htmlBody"

                # Fallback: RTF Body?
                if not body_content:
                    try:
                        # Some messages only have RTF.
                        # extract-msg < 0.28 didn't auto-decompress, but 0.55 should.
                        if hasattr(msg, 'rtfBody') and msg.rtfBody:
                             body_content = msg.rtfBody
                             source = "rtfBody"
                    except Exception:
                        pass

                # Ensure string decoding
                if isinstance(body_content, bytes):
                    try:
                        body_content = body_content.decode('utf-8', errors='replace')
                    except Exception as e:
                        logger.warning(f"Failed to decode MSG body bytes: {e}")
                        body_content = str(body_content)

                if body_content:
                    logger.info(f"Extracted body from {source} (len={len(body_content)}) for {filename}")
                else:
                    logger.warning(f"No body content found for MSG file: {filename}")

                result['body'] = body_content if body_content else ""

                msg.close()
            except Exception as e:
                logger.error(f"Critical error extracting MSG content: {e}", exc_info=True)
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
            logger.info(f"Extracted {len(result['indicators'].get('urls', []))} URLs from {filename}")
        else:
            logger.warning(f"No body content extracted for {filename}, skipping indicator extraction")

    except Exception as e:
        logger.error(f"Error parsing email {filename}: {e}", exc_info=True)
        raise e

    return result
