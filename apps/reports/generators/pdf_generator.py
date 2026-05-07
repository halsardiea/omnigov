"""
PDF Report Generator using WeasyPrint.

Generates compliance and vulnerability assessment reports as PDF documents.
"""
import logging
from datetime import datetime
from io import BytesIO

from django.template.loader import render_to_string

from .framework_analysis import build_framework_finding_entry

logger = logging.getLogger(__name__)


def _render_pdf(html_string: str) -> BytesIO:
    """Convert an HTML string to a PDF buffer with a pure-Python fallback on Windows."""
    buffer = BytesIO()

    try:
        from weasyprint import HTML

        HTML(string=html_string).write_pdf(buffer)
    except Exception as weasyprint_error:
        logger.warning('WeasyPrint unavailable, falling back to xhtml2pdf: %s', weasyprint_error)
        try:
            from xhtml2pdf import pisa
        except Exception as fallback_error:
            raise RuntimeError('No PDF backend is available. Install WeasyPrint dependencies or xhtml2pdf.') from fallback_error

        result = pisa.CreatePDF(src=html_string, dest=buffer, encoding='utf-8')
        if result.err:
            raise RuntimeError('xhtml2pdf failed to render the PDF output.')

    buffer.seek(0)
    return buffer


def generate_executive_pdf(scan_task, findings_with_ai, framework, alignment_summary) -> BytesIO:
    """
    Generate an executive compliance summary PDF.

    Returns a BytesIO buffer containing the PDF.
    """
    findings_with_ai = list(findings_with_ai)
    finding_entries = [build_framework_finding_entry(finding, framework) for finding in findings_with_ai]
    total_findings = len(finding_entries)
    high_count = sum(1 for entry in finding_entries if entry['finding'].severity == 'High')
    total_controls = framework.controls.count()
    impacted_controls = alignment_summary['impacted_controls_count']
    passing = max(total_controls - impacted_controls, 0)
    failing = impacted_controls
    compliance_score = alignment_summary['compliance_score']

    # Severity breakdown
    severity_counts = {}
    for entry in finding_entries:
        sev = entry['finding'].severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    context = {
        'scan_task': scan_task,
        'framework': framework,
        'finding_entries': finding_entries,
        'compliance_score': compliance_score,
        'total_findings': total_findings,
        'total_controls': total_controls,
        'passing_count': passing,
        'failing_count': failing,
        'severity_counts': severity_counts,
        'generated_at': datetime.now(),
        'report_type': 'Executive Summary',
        'alignment_summary': alignment_summary,
    }

    html_string = render_to_string('reports/pdf/executive_report.html', context)
    return _render_pdf(html_string)


def generate_technical_pdf(scan_task, findings_with_ai, framework, alignment_summary) -> BytesIO:
    """
    Generate a detailed technical findings PDF with remediation guidance.

    Returns a BytesIO buffer containing the PDF.
    """
    findings_with_ai = list(findings_with_ai)
    finding_entries = [build_framework_finding_entry(finding, framework) for finding in findings_with_ai]
    # Group findings by severity
    findings_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
    for entry in finding_entries:
        sev = entry['finding'].severity
        if sev in findings_by_severity:
            findings_by_severity[sev].append(entry)

    # Calculate metrics
    total = len(finding_entries)
    high_count = len(findings_by_severity.get('High', []))

    context = {
        'scan_task': scan_task,
        'framework': framework,
        'findings_by_severity': findings_by_severity,
        'total_findings': total,
        'high_findings': high_count,
        'generated_at': datetime.now(),
        'report_type': 'Technical Assessment',
        'alignment_summary': alignment_summary,
    }

    html_string = render_to_string('reports/pdf/technical_report.html', context)
    return _render_pdf(html_string)
