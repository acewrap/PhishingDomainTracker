from datetime import datetime
from sqlalchemy.orm import joinedload
from app.models import User, APIKey, PhishingDomain, ThreatTerm, EmailEvidence, EvidenceCorrelation, Task
from app.extensions import db

def generate_backup_data():
    """Generates a dictionary containing all database records."""
    # Serialize Users
    users = []
    for user in User.query.all():
        u_data = {
            'username': user.username,
            'password_hash': user.password_hash,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
            'password_expired': user.password_expired,
            'is_admin': user.is_admin
        }
        users.append(u_data)

    # Serialize API Keys
    api_keys = []
    for key in APIKey.query.all():
        k_data = {
            'user_username': key.user.username, # Store username to resolve relationship
            'access_key': key.access_key,
            'secret_hash': key.secret_hash,
            'created_at': key.created_at.isoformat() if key.created_at else None,
            'last_used_at': key.last_used_at.isoformat() if key.last_used_at else None
        }
        api_keys.append(k_data)

    # Serialize Phishing Domains
    domains = []
    for domain in PhishingDomain.query.all():
        d_data = {
            'id': domain.id, # Store ID for mapping if needed, though we primarily use domain_name
            'domain_name': domain.domain_name,
            'registration_status': domain.registration_status,
            'registration_date': domain.registration_date.isoformat() if domain.registration_date else None,
            'is_active': domain.is_active,
            'has_login_page': domain.has_login_page,
            'date_entered': domain.date_entered.isoformat() if domain.date_entered else None,
            'action_taken': domain.action_taken,
            'date_remediated': domain.date_remediated.isoformat() if domain.date_remediated else None,
            'screenshot_link': domain.screenshot_link,
            'registrar': domain.registrar,
            'ip_address': domain.ip_address,
            'urlscan_uuid': domain.urlscan_uuid,
            'has_mx_record': domain.has_mx_record,
            'manual_status': domain.manual_status,
            'asn_number': domain.asn_number,
            'asn_org': domain.asn_org,
            'favicon_mmh3': domain.favicon_mmh3,
            'jarm_hash': domain.jarm_hash,
            'html_artifacts': domain.html_artifacts
        }
        domains.append(d_data)

    # Serialize Threat Terms
    threat_terms = []
    for term in ThreatTerm.query.all():
        t_data = {
            'term': term.term
        }
        threat_terms.append(t_data)

    # Serialize Email Evidence
    evidence = []
    for ev in EmailEvidence.query.options(joinedload(EmailEvidence.user)).all():
        e_data = {
            'id': ev.id,
            'filename': ev.filename,
            'headers': ev.headers,
            'body': ev.body,
            'extracted_indicators': ev.extracted_indicators,
            'analysis_report': ev.analysis_report,
            'submitted_by_username': ev.user.username if ev.user else None,
            'submitted_at': ev.submitted_at.isoformat() if ev.submitted_at else None
        }
        evidence.append(e_data)

    # Serialize Evidence Correlations
    correlations = []
    for corr in EvidenceCorrelation.query.options(joinedload(EvidenceCorrelation.domain)).all():
        c_data = {
            'evidence_old_id': corr.evidence_id,
            'domain_name': corr.domain.domain_name, # Link by unique domain name
            'correlation_type': corr.correlation_type,
            'details': corr.details,
            'created_at': corr.created_at.isoformat() if corr.created_at else None
        }
        correlations.append(c_data)

    # Serialize Tasks
    tasks = []
    for task in Task.query.all():
        t_data = {
            'task_type': task.task_type,
            'payload': task.payload,
            'status': task.status,
            'result': task.result,
            'created_at': task.created_at.isoformat() if task.created_at else None,
            'updated_at': task.updated_at.isoformat() if task.updated_at else None
        }
        tasks.append(t_data)

    return {
        'users': users,
        'api_keys': api_keys,
        'domains': domains,
        'threat_terms': threat_terms,
        'email_evidence': evidence,
        'evidence_correlations': correlations,
        'tasks': tasks
    }

def perform_restore(data):
    """Restores the database from the provided dictionary data.

    Raises ValueError if data structure is invalid.
    """
    required_keys = ['users', 'api_keys', 'domains'] # Minimal requirement
    if not all(k in data for k in required_keys):
        raise ValueError('Invalid backup file format. Missing required keys.')

    try:
        # --- DANGER ZONE: WIPE DATA ---
        EvidenceCorrelation.query.delete()
        EmailEvidence.query.delete()
        APIKey.query.delete()
        Task.query.delete()
        ThreatTerm.query.delete()
        PhishingDomain.query.delete()
        User.query.delete() # Users last because of FKs (wait, APIKey depends on User, so APIKey first)

        # Correct Order of Deletion (Reverse of dependency)
        # EvidenceCorrelation -> EmailEvidence, PhishingDomain
        # EmailEvidence -> User
        # APIKey -> User
        # PhishingDomain -> None
        # Task -> None
        # ThreatTerm -> None
        # User -> None

        # --- RESTORE ZONE ---

        # 1. Restore Users
        user_map = {} # username -> new_id
        for u_data in data['users']:
            user = User(
                username=u_data['username'],
                password_hash=u_data['password_hash'],
                created_at=datetime.fromisoformat(u_data['created_at']) if u_data['created_at'] else None,
                last_login_at=datetime.fromisoformat(u_data['last_login_at']) if u_data['last_login_at'] else None,
                password_expired=u_data['password_expired'],
                is_admin=u_data['is_admin']
            )
            db.session.add(user)
            db.session.flush() # Generate ID
            user_map[user.username] = user.id

        # 2. Restore API Keys
        for k_data in data['api_keys']:
            user_id = user_map.get(k_data['user_username'])
            if user_id:
                api_key = APIKey(
                    user_id=user_id,
                    access_key=k_data['access_key'],
                    secret_hash=k_data['secret_hash'],
                    created_at=datetime.fromisoformat(k_data['created_at']) if k_data['created_at'] else None,
                    last_used_at=datetime.fromisoformat(k_data['last_used_at']) if k_data['last_used_at'] else None
                )
                db.session.add(api_key)

        # 3. Restore Domains
        domain_map = {} # domain_name -> new_id
        for d_data in data['domains']:
            domain = PhishingDomain(
                domain_name=d_data['domain_name'],
                registration_status=d_data.get('registration_status'),
                registration_date=datetime.fromisoformat(d_data['registration_date']) if d_data.get('registration_date') else None,
                is_active=d_data.get('is_active', False),
                has_login_page=d_data.get('has_login_page', False),
                date_entered=datetime.fromisoformat(d_data['date_entered']) if d_data.get('date_entered') else datetime.utcnow(),
                action_taken=d_data.get('action_taken'),
                date_remediated=datetime.fromisoformat(d_data['date_remediated']) if d_data.get('date_remediated') else None,
                screenshot_link=d_data.get('screenshot_link'),
                registrar=d_data.get('registrar'),
                ip_address=d_data.get('ip_address'),
                urlscan_uuid=d_data.get('urlscan_uuid'),
                has_mx_record=d_data.get('has_mx_record', False),
                manual_status=d_data.get('manual_status'),
                # New fields
                asn_number=d_data.get('asn_number'),
                asn_org=d_data.get('asn_org'),
                favicon_mmh3=d_data.get('favicon_mmh3'),
                jarm_hash=d_data.get('jarm_hash'),
                html_artifacts=d_data.get('html_artifacts')
            )
            db.session.add(domain)
            db.session.flush()
            domain_map[domain.domain_name] = domain.id

        # 4. Restore Threat Terms
        if 'threat_terms' in data:
            for t_data in data['threat_terms']:
                term = ThreatTerm(term=t_data['term'])
                db.session.add(term)

        # 5. Restore Email Evidence
        evidence_id_map = {} # old_id -> new_id
        if 'email_evidence' in data:
            for e_data in data['email_evidence']:
                user_id = user_map.get(e_data.get('submitted_by_username'))
                ev = EmailEvidence(
                    filename=e_data.get('filename'),
                    headers=e_data.get('headers'),
                    body=e_data.get('body'),
                    extracted_indicators=e_data.get('extracted_indicators'),
                    analysis_report=e_data.get('analysis_report'),
                    submitted_by=user_id,
                    submitted_at=datetime.fromisoformat(e_data['submitted_at']) if e_data.get('submitted_at') else None
                )
                db.session.add(ev)
                db.session.flush()
                evidence_id_map[e_data.get('id')] = ev.id

        # 6. Restore Evidence Correlations
        if 'evidence_correlations' in data:
            for c_data in data['evidence_correlations']:
                new_evidence_id = evidence_id_map.get(c_data.get('evidence_old_id'))
                new_domain_id = domain_map.get(c_data.get('domain_name'))

                if new_evidence_id and new_domain_id:
                    corr = EvidenceCorrelation(
                        evidence_id=new_evidence_id,
                        domain_id=new_domain_id,
                        correlation_type=c_data.get('correlation_type'),
                        details=c_data.get('details'),
                        created_at=datetime.fromisoformat(c_data['created_at']) if c_data.get('created_at') else None
                    )
                    db.session.add(corr)

        # 7. Restore Tasks
        if 'tasks' in data:
            for t_data in data['tasks']:
                task = Task(
                    task_type=t_data.get('task_type'),
                    payload=t_data.get('payload'),
                    status=t_data.get('status'),
                    result=t_data.get('result'),
                    created_at=datetime.fromisoformat(t_data['created_at']) if t_data.get('created_at') else None,
                    updated_at=datetime.fromisoformat(t_data['updated_at']) if t_data.get('updated_at') else None
                )
                db.session.add(task)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e
