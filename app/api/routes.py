from flask import Blueprint, jsonify, request, abort
from app.models import PhishingDomain, APIKey
from app.extensions import db
import hashlib
from functools import wraps
from datetime import datetime

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
