"""
PDF Report Generator using WeasyPrint.

Generates compliance and vulnerability assessment reports as PDF documents.
"""
import logging
from datetime import datetime
from io import BytesIO

from django.template.loader import render_to_string
from weasyprint import HTML

logger = logging.getLogger(__name__)


def _render_pdf(html_string: str) -> BytesIO:
    """Convert an HTML string to a PDF BytesIO buffer using WeasyPrint."""
    buffer = BytesIO()
    HTML(string=html_string).write_pdf(buffer)
    buffer.seek(0)
    return buffer


def generate_executive_pdf(scan_task, findings_with_ai, framework) -> BytesIO:
    """
    Generate an executive compliance summary PDF.

    Returns a BytesIO buffer containing the PDF.
    """
    # Calculate compliance metrics (severity-based placeholder until AI is re-enabled)
    total_controls = findings_with_ai.count()
    high_count = sum(1 for f in findings_with_ai if f.severity == 'High')
    passing = total_controls - high_count
    failing = high_count
    compliance_score = round((passing / max(total_controls, 1)) * 100, 1)

    # Severity breakdown
    severity_counts = {}
    for finding in findings_with_ai:
        sev = finding.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    context = {
        'scan_task': scan_task,
        'framework': framework,
        'findings': findings_with_ai,
        'compliance_score': compliance_score,
        'total_findings': total_controls,
        'passing_count': passing,
        'failing_count': failing,
        'severity_counts': severity_counts,
        'generated_at': datetime.now(),
        'report_type': 'Executive Summary',
    }

    html_string = render_to_string('reports/pdf/executive_report.html', context)
    return _render_pdf(html_string)


def generate_technical_pdf(scan_task, findings_with_ai, framework) -> BytesIO:
    """
    Generate a detailed technical findings PDF with remediation guidance.

    Returns a BytesIO buffer containing the PDF.
    """
    # Group findings by severity
    findings_by_severity = {'High': [], 'Medium': [], 'Low': []}
    for finding in findings_with_ai:
        sev = finding.severity
        if sev in findings_by_severity:
            findings_by_severity[sev].append(finding)

    # Calculate metrics
    total = findings_with_ai.count()
    high_count = len(findings_by_severity.get('High', []))

    context = {
        'scan_task': scan_task,
        'framework': framework,
        'findings_by_severity': findings_by_severity,
        'total_findings': total,
        'high_findings': high_count,
        'generated_at': datetime.now(),
        'report_type': 'Technical Assessment',
    }

    html_string = render_to_string('reports/pdf/technical_report.html', context)
    return _render_pdf(html_string)
