from flask import Blueprint, jsonify, request, abort, g
from app.models import PhishingDomain, APIKey, EmailEvidence
from app.extensions import db
from app.backup_service import generate_backup_data, perform_restore
from app.queue_service import add_task
from werkzeug.utils import secure_filename
import hashlib
from functools import wraps
from datetime import datetime
import os
import uuid
import json

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_key = request.headers.get('X-API-Key')
        secret_key = request.headers.get('X-API-Secret')

        if not access_key or not secret_key:
            return jsonify({'error': 'Missing API Key or Secret'}), 401

        api_key = APIKey.query.filter_by(access_key=access_key).first()

        if not api_key:
            return jsonify({'error': 'Invalid API Key'}), 401

        # Verify Secret
        secret_hash = hashlib.sha256(secret_key.encode()).hexdigest()
        if secret_hash != api_key.secret_hash:
             return jsonify({'error': 'Invalid API Secret'}), 401

        # Update last used
        api_key.last_used_at = datetime.utcnow()
        db.session.commit()

        g.api_user = api_key.user

        return f(*args, **kwargs)
    return decorated_function

@api_v1.route('/domains', methods=['GET'])
@require_api_key
def get_domains():
    domains = PhishingDomain.query.all()
    results = []
    for d in domains:
        results.append({
            'id': d.id,
            'domain_name': d.domain_name,
            'threat_status': d.threat_status,
            'date_entered': d.date_entered.isoformat() if d.date_entered else None,
            'is_active': d.is_active,
            'has_login_page': d.has_login_page
        })
    return jsonify(results)

@api_v1.route('/domains', methods=['POST'])
@require_api_key
def add_domain():
    data = request.get_json()
    if not data or 'domain_name' not in data:
         return jsonify({'error': 'Missing domain_name'}), 400

    domain_name = data['domain_name']

    existing = PhishingDomain.query.filter_by(domain_name=domain_name).first()
    if existing:
         return jsonify({'message': 'Domain already exists', 'id': existing.id}), 200

    new_domain = PhishingDomain(domain_name=domain_name)
    db.session.add(new_domain)
    db.session.commit()

    return jsonify({'message': 'Domain added', 'id': new_domain.id}), 201

@api_v1.route('/evidence', methods=['POST'])
@require_api_key
def upload_evidence():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    if not (filename.lower().endswith('.eml') or filename.lower().endswith('.msg')):
        return jsonify({'error': 'Invalid file type. Only .eml and .msg supported.'}), 400

    unique_filename = f"{uuid.uuid4()}_{filename}"

    # Ensure uploads directory (relative to where app is run, typically root)
    # Using 'uploads' as per app.py logic
    upload_dir = 'uploads'
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)

    filepath = os.path.join(upload_dir, unique_filename)
    file.save(filepath)

    # Create Evidence Record
    evidence = EmailEvidence(
        filename=filename,
        submitted_by=g.api_user.id
    )
    db.session.add(evidence)
    db.session.commit()

    # Add Task
    add_task('process_email', {'evidence_id': evidence.id, 'filepath': filepath})

    return jsonify({'message': 'Evidence uploaded and processing started', 'id': evidence.id}), 201

@api_v1.route('/evidence/<int:id>', methods=['GET'])
@require_api_key
def get_evidence(id):
    evidence = EmailEvidence.query.get(id)
    if not evidence:
        return jsonify({'error': 'Evidence not found'}), 404

    # Check permission? Currently API Key user can see anything or just their own?
    # Logic in require_api_key sets g.api_user. Admin sees all?
    # For now, simplistic: if you have a valid API key, you can query by ID.

    indicators = {}
    if evidence.extracted_indicators:
        try:
             indicators = json.loads(evidence.extracted_indicators)
        except:
             pass

    analysis = {}
    if evidence.analysis_report:
        try:
            analysis = json.loads(evidence.analysis_report)
        except:
            pass

    return jsonify({
        'id': evidence.id,
        'filename': evidence.filename,
        'submitted_at': evidence.submitted_at.isoformat(),
        'submitted_by': evidence.user.username if evidence.user else None,
        'extracted_indicators': indicators,
        'analysis_report': analysis,
        'correlations_count': len(evidence.correlations)
    })

@api_v1.route('/backup', methods=['GET'])
@require_api_key
def backup():
    if not g.api_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403

    backup_data = generate_backup_data()
    return jsonify(backup_data)

@api_v1.route('/restore', methods=['POST'])
@require_api_key
def restore():
    if not g.api_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    try:
        perform_restore(data)
        return jsonify({'message': 'Database restored successfully'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Restore failed: {str(e)}'}), 500
