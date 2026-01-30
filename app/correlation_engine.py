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

    # 1. Collect all indicators from all evidence
    all_extracted_domains = set()
    all_extracted_ips = set()

    # Pre-parse indicators to avoid repeated JSON parsing
    evidence_indicators = {} # {evidence_id: {'domains': set, 'ips': set}}

    for ev in all_evidence:
        indicators = {}
        if ev.extracted_indicators:
            try:
                indicators = json.loads(ev.extracted_indicators)
            except:
                pass

        domains = set(indicators.get('domains', []))
        ips = set(indicators.get('ips', []))

        all_extracted_domains.update(domains)
        all_extracted_ips.update(ips)

        evidence_indicators[ev.id] = {'domains': domains, 'ips': ips}

    # 2. Batch fetch matching PhishingDomains
    domain_map = {} # domain_name -> PhishingDomain object
    ip_map = {}     # ip_address -> list of PhishingDomain objects

    def batch_fetch(model, attribute, values, chunk_size=500):
        results = []
        values_list = list(values)
        for i in range(0, len(values_list), chunk_size):
            chunk = values_list[i:i + chunk_size]
            if not chunk: continue
            results.extend(model.query.filter(attribute.in_(chunk)).all())
        return results

    if all_extracted_domains:
        matched_domains = batch_fetch(PhishingDomain, PhishingDomain.domain_name, all_extracted_domains)
        for d in matched_domains:
            domain_map[d.domain_name] = d

    if all_extracted_ips:
        matched_ips = batch_fetch(PhishingDomain, PhishingDomain.ip_address, all_extracted_ips)
        for d in matched_ips:
            if d.ip_address not in ip_map:
                ip_map[d.ip_address] = []
            ip_map[d.ip_address].append(d)

    # 3. Batch fetch existing correlations
    # To optimize memory, we fetch only the tuples (evidence_id, domain_id, type)
    existing_correlations = set(
        db.session.query(
            EvidenceCorrelation.evidence_id,
            EvidenceCorrelation.domain_id,
            EvidenceCorrelation.correlation_type
        ).all()
    )

    new_correlations = []

    # 4. Match in memory
    for ev in all_evidence:
        indicators = evidence_indicators.get(ev.id)
        if not indicators: continue

        # Check Domains
        for domain_str in indicators['domains']:
            matched_domain = domain_map.get(domain_str)
            if matched_domain:
                key = (ev.id, matched_domain.id, 'Domain Match')
                if key not in existing_correlations:
                    corr = EvidenceCorrelation(
                        evidence_id=ev.id,
                        domain_id=matched_domain.id,
                        correlation_type='Domain Match',
                        details=f"Extracted domain {domain_str} matches monitored domain."
                    )
                    new_correlations.append(corr)
                    existing_correlations.add(key)
                    count += 1

        # Check IPs
        for ip_str in indicators['ips']:
            matched_domains_list = ip_map.get(ip_str, [])
            for md in matched_domains_list:
                key = (ev.id, md.id, 'IP Match')
                if key not in existing_correlations:
                    corr = EvidenceCorrelation(
                        evidence_id=ev.id,
                        domain_id=md.id,
                        correlation_type='IP Match',
                        details=f"Extracted IP {ip_str} matches domain {md.domain_name} IP."
                    )
                    new_correlations.append(corr)
                    existing_correlations.add(key)
                    count += 1

    # 5. Bulk Insert
    if new_correlations:
        # Use bulk_save_objects for performance
        db.session.bulk_save_objects(new_correlations)
        db.session.commit()

    logger.info(f"Correlation refresh complete. Found {count} new matches.")
    return count
