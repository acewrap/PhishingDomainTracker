from flask import render_template, request, send_file, flash, redirect, url_for
from flask_login import login_required
from app.dashboard import dashboard_bp
from app.models import PhishingDomain
from app.reporting import generate_quarterly_report_data, generate_quarterly_pdf
from collections import Counter
from datetime import datetime

@dashboard_bp.route('/dashboard')
@login_required
def index():
    domains = PhishingDomain.query.all()

    # Infrastructure Stats
    registrars = [d.registrar for d in domains if d.registrar]
    registrar_counts = dict(Counter(registrars).most_common(10))

    asns = [d.asn_org for d in domains if d.asn_org]
    asn_counts = dict(Counter(asns).most_common(10))

    # NS Records (Top Providers approximation)
    ns_list = []
    for d in domains:
        if d.ns_records:
            records = d.ns_records.split('\n')
            for r in records:
                r = r.strip().strip('.')
                if r:
                     parts = r.split('.')
                     if len(parts) >= 2:
                         ns_list.append(".".join(parts[-2:]))
                     else:
                         ns_list.append(r)
    ns_counts = dict(Counter(ns_list).most_common(10))

    # Activity Over Time (By Month)
    dates = [d.date_entered.strftime('%Y-%m') for d in domains if d.date_entered]
    activity_counts = dict(Counter(dates))
    sorted_activity = dict(sorted(activity_counts.items()))

    # Threat Status
    statuses = [d.threat_status for d in domains]
    status_counts = dict(Counter(statuses))

    current_year = datetime.now().year
    years = range(current_year, current_year - 5, -1)

    return render_template(
        'dashboard/index.html',
        registrar_counts=registrar_counts,
        asn_counts=asn_counts,
        ns_counts=ns_counts,
        activity_counts=sorted_activity,
        status_counts=status_counts,
        years=years
    )

@dashboard_bp.route('/dashboard/report/quarterly', methods=['POST'])
@login_required
def quarterly_report():
    try:
        year = int(request.form.get('year'))
        quarter = int(request.form.get('quarter'))

        data = generate_quarterly_report_data(year, quarter)
        pdf_file = generate_quarterly_pdf(data)

        return send_file(
            pdf_file,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'Quarterly_Report_Q{quarter}_{year}.pdf'
        )
    except Exception as e:
        flash(f"Error generating report: {e}", "danger")
        return redirect(url_for('dashboard.index'))
