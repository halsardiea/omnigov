"""
CSV Report Generator.

Generates findings export as CSV files for spreadsheet analysis.
"""
import csv
import logging
from io import StringIO

from .framework_analysis import build_framework_finding_entry

logger = logging.getLogger(__name__)


def generate_findings_csv(scan_task, findings_with_ai, framework) -> StringIO:
    """
    Generate a CSV export of all findings with AI compliance analysis.

    Returns a StringIO buffer with CSV content.
    """
    buffer = StringIO()
    writer = csv.writer(buffer)

    # Header row
    writer.writerow([
        'Finding Name',
        'CVE IDs',
        'CVSS Score',
        'Severity',
        'Host',
        'Port',
        'Description',
        'Solution',
        'Matched Controls',
        'Executive Summary',
        'Technical Remediation',
        'Analysis Method',
    ])

    for finding in findings_with_ai:
        analysis = build_framework_finding_entry(finding, framework)
        matched_controls = ''
        executive_summary = ''
        technical_remediation = ''
        analysis_method = ''
        if analysis:
            framework_controls = analysis['matched_controls']
            matched_controls = '; '.join(
                f"{item.get('control_id')} {item.get('title')}".strip()
                for item in framework_controls
            )
            executive_summary = analysis['executive_summary'] or ''
            technical_remediation = analysis['technical_remediation'] or ''
            analysis_method = analysis['analysis_method'] or ''

        writer.writerow([
            finding.name,
            ', '.join(finding.cve_ids) if finding.cve_ids else '',
            finding.cvss_score or '',
            finding.severity,
            finding.host,
            finding.port,
            finding.description or '',
            finding.solution or '',
            matched_controls,
            executive_summary,
            technical_remediation,
            analysis_method,
        ])

    buffer.seek(0)
    return buffer
