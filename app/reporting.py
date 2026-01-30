from flask import render_template
from weasyprint import HTML
from app.models import EmailEvidence, PhishingDomain
import json
import io
import openpyxl
from datetime import datetime
from collections import Counter
import calendar

def generate_evidence_pdf(evidence_id):
    """
    Generates a PDF report for the given evidence ID.
    Returns bytes.
    """
    evidence = EmailEvidence.query.get(evidence_id)
    if not evidence:
        return None

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

    # Render HTML
    html_string = render_template(
        'pdf_report.html',
        evidence=evidence,
        indicators=indicators,
        analysis=analysis
    )

    # Convert to PDF
    pdf_file = io.BytesIO()
    HTML(string=html_string).write_pdf(pdf_file)
    pdf_file.seek(0)

    return pdf_file

def generate_excel_report(domains):
    """
    Generates an Excel report for the given list of PhishingDomain objects.
    Returns BytesIO.
    """
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Phishing Domains"

    headers = [
        'ID', 'Domain Name', 'Registration Status', 'Is Active',
        'Has Login Page', 'Date Entered', 'Action Taken',
        'Date Remediated', 'Screenshot Link', 'Registrar',
        'IP Address', 'Urlscan UUID', 'Has MX Record',
        'MX Records', 'NS Records',
        'Manual Status', 'Threat Status'
    ]
    sheet.append(headers)

    for d in domains:
        row = [
            d.id,
            d.domain_name,
            d.registration_status,
            d.is_active,
            d.has_login_page,
            d.date_entered.strftime('%Y-%m-%d %H:%M:%S') if d.date_entered else '',
            d.action_taken,
            d.date_remediated.strftime('%Y-%m-%d %H:%M:%S') if d.date_remediated else '',
            d.screenshot_link,
            d.registrar,
            d.ip_address,
            d.urlscan_uuid,
            d.has_mx_record,
            d.mx_records,
            d.ns_records,
            d.manual_status,
            d.threat_status
        ]
        sheet.append(row)

    output = io.BytesIO()
    workbook.save(output)
    output.seek(0)
    return output

def get_quarter_dates(year, quarter):
    start_month = (quarter - 1) * 3 + 1
    end_month = start_month + 2

    start_date = datetime(year, start_month, 1)

    last_day = calendar.monthrange(year, end_month)[1]
    end_date = datetime(year, end_month, last_day, 23, 59, 59)

    return start_date, end_date

def generate_quarterly_report_data(year, quarter):
    start_date, end_date = get_quarter_dates(year, quarter)

    domains = PhishingDomain.query.filter(
        PhishingDomain.date_entered >= start_date,
        PhishingDomain.date_entered <= end_date
    ).all()

    total_domains = len(domains)
    takedowns = [d for d in domains if d.date_remediated]
    total_takedowns = len(takedowns)
    takedown_rate = (total_takedowns / total_domains * 100) if total_domains > 0 else 0

    remediation_times = []
    for d in takedowns:
        if d.date_entered and d.date_remediated:
            delta = d.date_remediated - d.date_entered
            remediation_times.append(delta.total_seconds() / 3600) # hours

    avg_remediation_hours = sum(remediation_times) / len(remediation_times) if remediation_times else 0

    registrars = [d.registrar for d in domains if d.registrar]
    top_registrars = Counter(registrars).most_common(5)

    asns = [d.asn_org for d in domains if d.asn_org]
    top_asns = Counter(asns).most_common(5)

    return {
        'year': year,
        'quarter': quarter,
        'start_date': start_date,
        'end_date': end_date,
        'total_domains': total_domains,
        'total_takedowns': total_takedowns,
        'takedown_rate': round(takedown_rate, 2),
        'avg_remediation_hours': round(avg_remediation_hours, 2),
        'top_registrars': top_registrars,
        'top_asns': top_asns,
        'domains': domains
    }

def generate_quarterly_pdf(data):
    html_string = render_template(
        'quarterly_report.html',
        data=data
    )

    pdf_file = io.BytesIO()
    HTML(string=html_string).write_pdf(pdf_file)
    pdf_file.seek(0)
    return pdf_file
