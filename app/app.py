from flask import Flask, render_template, request, redirect, url_for, flash
from app.models import db, PhishingDomain
from app.utils import enrich_domain
from datetime import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///domains.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')

db.init_app(app)

@app.route('/')
def index():
    domains = PhishingDomain.query.order_by(PhishingDomain.date_entered.desc()).all()
    return render_template('index.html', domains=domains)

@app.route('/add', methods=['GET', 'POST'])
def add_domain():
    if request.method == 'POST':
        domain_name = request.form.get('domain_name')
        if domain_name:
            # Check if exists
            existing = PhishingDomain.query.filter_by(domain_name=domain_name).first()
            if existing:
                flash(f'Domain {domain_name} already exists.', 'warning')
                return redirect(url_for('domain_details', id=existing.id))
            
            new_domain = PhishingDomain(domain_name=domain_name)
            
            # Optional: auto-enrich on add
            if request.form.get('auto_enrich'):
                 enrich_domain(new_domain)
            
            db.session.add(new_domain)
            db.session.commit()
            flash(f'Domain {domain_name} added successfully.', 'success')
            return redirect(url_for('index'))
    return render_template('add_domain.html')

@app.route('/domain/<int:id>')
def domain_details(id):
    domain = PhishingDomain.query.get_or_404(id)
    return render_template('domain_detail.html', domain=domain)

@app.route('/enrich/<int:id>', methods=['POST'])
def enrich_domain_route(id):
    domain = PhishingDomain.query.get_or_404(id)
    enrich_domain(domain)
    db.session.commit()
    flash(f'Enrichment triggered for {domain.domain_name}', 'info')
    return redirect(url_for('domain_details', id=domain.id))

@app.route('/update/<int:id>', methods=['POST'])
def update_domain(id):
    domain = PhishingDomain.query.get_or_404(id)
    
    domain.action_taken = request.form.get('action_taken')
    
    # Handle date_remediated
    date_rem_str = request.form.get('date_remediated')
    if date_rem_str:
        try:
             # HTML date input returns YYYY-MM-DD
             domain.date_remediated = datetime.strptime(date_rem_str, '%Y-%m-%d')
        except ValueError:
             pass # Keep old value or ignore error
    else:
        domain.date_remediated = None

    domain.is_active = 'is_active' in request.form
    domain.has_login_page = 'has_login_page' in request.form
    domain.manual_status = request.form.get('manual_status')
    
    db.session.commit()
    flash('Domain updated successfully.', 'success')
    return redirect(url_for('domain_details', id=domain.id))

@app.route('/delete_domains', methods=['POST'])
def delete_domains():
    domain_ids = request.form.getlist('domain_ids')
    if domain_ids:
        # Check if "delete_all" or similar logic is needed, but assuming ID list for now
        PhishingDomain.query.filter(PhishingDomain.id.in_(domain_ids)).delete(synchronize_session=False)
        db.session.commit()
        flash(f'{len(domain_ids)} domains deleted successfully.', 'success')
    else:
        flash('No domains selected for deletion.', 'warning')
    return redirect(url_for('index'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    app.run(debug=debug_mode, host='0.0.0.0')
