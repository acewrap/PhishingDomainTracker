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

    # Helper for Chart.js data
    def prepare_chart_data(counter_obj, limit=None):
        if limit:
            data = counter_obj.most_common(limit)
            return [x[0] for x in data], [x[1] for x in data]
        else:
            return list(counter_obj.keys()), list(counter_obj.values())

    # Infrastructure Stats
    registrars = [d.registrar for d in domains if d.registrar]
    registrar_labels, registrar_data = prepare_chart_data(Counter(registrars), 10)

    asns = [d.asn_org for d in domains if d.asn_org]
    asn_labels, asn_data = prepare_chart_data(Counter(asns), 10)

    # NS Records (Top Providers approximation)
    ns_list = []
    for d in domains:
        if d.ns_records:
            # robust splitting
            records = [r.strip() for r in d.ns_records.replace('\r', '').split('\n') if r.strip()]
            for r in records:
                r = r.strip('.')
                if r:
                     parts = r.split('.')
                     if len(parts) >= 2:
                         ns_list.append(".".join(parts[-2:]))
                     else:
                         ns_list.append(r)
    ns_labels, ns_data = prepare_chart_data(Counter(ns_list), 10)

    # Activity Over Time (By Month)
    dates = [d.date_entered.strftime('%Y-%m') for d in domains if d.date_entered]
    activity_counter = Counter(dates)
    # Sort by date
    sorted_dates = sorted(activity_counter.keys())
    activity_labels = sorted_dates
    activity_data_list = [activity_counter[d] for d in sorted_dates]

    # Threat Status
    statuses = [d.threat_status for d in domains]
    status_counter = Counter(statuses)
    status_labels = list(status_counter.keys())
    status_data = list(status_counter.values())

    current_year = datetime.now().year
    years = range(current_year, current_year - 5, -1)

    return render_template(
        'dashboard/index.html',
        registrar_labels=registrar_labels, registrar_data=registrar_data,
        asn_labels=asn_labels, asn_data=asn_data,
        ns_labels=ns_labels, ns_data=ns_data,
        activity_labels=activity_labels, activity_data=activity_data_list,
        status_labels=status_labels, status_data=status_data,
        years=years
    )

@dashboard_bp.route('/dashboard/report/quarterly', methods=['POST'])
@login_required
def quarterly_report():
    try:
        year_str = request.form.get('year')
        quarter_str = request.form.get('quarter')

        if not year_str or not quarter_str:
             raise ValueError("Year and Quarter are required.")

        year = int(year_str)
        quarter = int(quarter_str)

        data = generate_quarterly_report_data(year, quarter)
        pdf_file = generate_quarterly_pdf(data)

        return send_file(
            pdf_file,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'Quarterly_Report_Q{quarter}_{year}.pdf'
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Error generating quarterly report: {e}", exc_info=True)
        flash(f"Error generating report: {str(e)}", "danger")
        return redirect(url_for('dashboard.index'))
