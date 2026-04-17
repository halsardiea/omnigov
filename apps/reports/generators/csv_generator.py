"""
CSV Report Generator.

Generates findings export as CSV files for spreadsheet analysis.
"""
import csv
import logging
from io import StringIO

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
    ])

    for finding in findings_with_ai:
        writer.writerow([
            finding.name,
            ', '.join(finding.cve_ids) if finding.cve_ids else '',
            finding.cvss_score or '',
            finding.severity,
            finding.host,
            finding.port,
            finding.description[:500] if finding.description else '',
            finding.solution[:500] if finding.solution else '',
        ])

    buffer.seek(0)
    return buffer
