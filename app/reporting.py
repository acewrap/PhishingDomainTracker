from flask import render_template
from weasyprint import HTML
from app.models import EmailEvidence
import json
import io

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
