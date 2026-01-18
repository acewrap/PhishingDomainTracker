import json
import logging
from app.models import EmailEvidence, PhishingDomain, EvidenceCorrelation
from app.extensions import db

logger = logging.getLogger(__name__)

def correlate_evidence(evidence_id):
    """
    Correlates a specific email evidence record against known phishing domains.
    """
    evidence = EmailEvidence.query.get(evidence_id)
    if not evidence:
        return 0

    indicators = {}
    if evidence.extracted_indicators:
        try:
            indicators = json.loads(evidence.extracted_indicators)
        except:
            pass

    extracted_domains = set(indicators.get('domains', []))
    extracted_ips = set(indicators.get('ips', []))
    extracted_urls = set(indicators.get('urls', []))

    new_matches = 0

    # 1. Check Domains
    for domain in extracted_domains:
        # Exact match
        matched_domain = PhishingDomain.query.filter_by(domain_name=domain).first()
        if matched_domain:
            if create_correlation(evidence, matched_domain, 'Domain Match', f"Extracted domain {domain} matches monitored domain."):
                new_matches += 1

    # 2. Check IPs
    for ip in extracted_ips:
        matched_domains = PhishingDomain.query.filter_by(ip_address=ip).all()
        for md in matched_domains:
            if create_correlation(evidence, md, 'IP Match', f"Extracted IP {ip} matches domain {md.domain_name} IP."):
                new_matches += 1

    # 3. Check URLs (fuzzy match - url contains domain)
    # This is expensive if we scan all domains.
    # Instead, we iterate extracted URLs and check if they contain any known domain.
    # But checking against ALL known domains is N*M.
    # Better: Extract hostname from URL (which we likely did in 'domains') and check that.
    # But if URL is IP based, we have that in IPs.
    # So 'Domain Match' and 'IP Match' cover most.
    # What if the PhishingDomain is a full URL (e.g. subpath)?
    # The model says `domain_name = db.Column(db.String(255))`. Usually it's a domain/hostname.
    # If `PhishingDomain` stores full URLs, we should check containment.

    # Let's assume `PhishingDomain` stores domains mostly.
    # But just in case, let's do a simple check:
    # If extracted URL contains monitored domain name.

    # We can skip this if we assume 'domains' extraction covered the hostnames.
    # The `extract_indicators` function extracts domains from URLs.
    # So checking 'domains' should be sufficient for hostname matches.

    return new_matches

def create_correlation(evidence, domain, type, details):
    """
    Creates a correlation record if it doesn't exist.
    """
    existing = EvidenceCorrelation.query.filter_by(
        evidence_id=evidence.id,
        domain_id=domain.id,
        correlation_type=type
    ).first()

    if not existing:
        corr = EvidenceCorrelation(
            evidence_id=evidence.id,
            domain_id=domain.id,
            correlation_type=type,
            details=details
        )
        db.session.add(corr)
        return True
    return False

def refresh_correlations():
    """
    Re-runs correlation for ALL evidence against ALL domains.
    This handles cases where new domains were added that match old evidence,
    or new evidence matches old domains (though that's handled on ingestion).
    """
    logger.info("Starting full correlation refresh...")
    count = 0
    all_evidence = EmailEvidence.query.all()
    for ev in all_evidence:
        count += correlate_evidence(ev.id)

    db.session.commit()
    logger.info(f"Correlation refresh complete. Found {count} new matches.")
    return count
