# ---
# LOCATION : apps/interceptor/xml_parser.py
# PURPOSE  : Converts the raw XML report produced by OpenVAS into structured Python
#            dicts that the rest of the pipeline can work with.
#            Uses defusedxml instead of the standard library's ElementTree to
#            prevent XML External Entity (XXE) attacks that could read files from
#            the server. A 50 MB size cap prevents XML bomb denial-of-service.
#
# CONNECTS TO:
#   - apps/interceptor/tasks.py       → process_scan_findings_pipeline() calls
#                                        parse_openvas_xml() and stores the results
#                                        as TechnicalFinding rows
#   - apps/scanner/models.py          → ScanTask.raw_report_xml is the XML string
#                                        passed into parse_openvas_xml()
#   - apps/scanner/gvm_client.py      → get_report() returns the XML string that
#                                        eventually reaches this parser
# ---
"""
OpenVAS XML Report Parser.

Parses the XML output from GVM/OpenVAS into structured Python dicts.
Uses defusedxml to prevent XXE attacks.
"""
import logging
from typing import Optional

import defusedxml.ElementTree as ET

logger = logging.getLogger(__name__)


# Safely pulls a text value from a nested XML element.
# Returns a default string instead of crashing if the element or its text is missing —
# OpenVAS XML is inconsistent across scanner versions, so defensive access is essential.
def _find_text(element, path: str, default: str = '') -> str:
    """Safely extract text from an XML element."""
    el = element.find(path)
    if el is not None and el.text:
        return el.text.strip()
    return default


# Pulls every CVE ID from a result's NVT reference block.
# CVE IDs are stored in TechnicalFinding.cve_ids and displayed on the detail page;
# they also give analysts a direct link to the NVD database entry.
def _extract_cves(result_element) -> list[str]:
    """Extract CVE IDs from a result's NVT refs."""
    cves = []
    for ref in result_element.findall('.//nvt/refs/ref'):
        if ref.get('type') == 'cve':
            cve_id = ref.get('id', '')
            if cve_id:
                cves.append(cve_id)
    return cves


# CVSS score is the primary sort key for findings (highest severity shown first).
# Two possible paths in the XML are tried because older OpenVAS versions place
# the score under <severity> while newer ones use <nvt><cvss_base>.
def _extract_cvss(result_element) -> Optional[float]:
    """Extract CVSS base score from NVT element."""
    text = _find_text(result_element, './/nvt/cvss_base')
    if not text:
        text = _find_text(result_element, './/severity')
    if text:
        try:
            return float(text)
        except ValueError:
            pass
    return None


# Quality of Detection (0–100) expresses how confident the scanner is that the
# finding is a true positive. A QoD below 70 is often filtered from production
# reports. Stored in TechnicalFinding.qod for display and future filtering.
def _extract_qod(result_element) -> Optional[int]:
    """Extract Quality of Detection value."""
    text = _find_text(result_element, './/qod/value')
    if text:
        try:
            return int(text)
        except ValueError:
            pass
    return None


# Collects NVD URLs and CVE detail links from the result's reference block.
# Stored in TechnicalFinding.references and rendered as clickable links on the
# scan detail page for the analyst to consult while writing a remediation plan.
def _extract_references(result_element) -> list[str]:
    """Extract reference URLs."""
    refs = []
    for ref in result_element.findall('.//nvt/refs/ref'):
        ref_type = ref.get('type', '')
        ref_id = ref.get('id', '')
        if ref_type == 'url' and ref_id:
            refs.append(ref_id)
        elif ref_type == 'cve' and ref_id:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{ref_id}")
    return refs


# GVM uses free-text threat labels ('High', 'Critical', 'Medium', etc.).
# This function normalises them to the exact strings in TechnicalFinding.Severity
# so the rest of the codebase can use safe comparisons.
def _map_threat_to_severity(threat: str) -> str:
    """Normalize threat strings to our Severity enum values."""
    mapping = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'log': 'Log',
        'alarm': 'Critical',
        'debug': 'Log',
    }
    return mapping.get(threat.lower().strip(), 'Log')


def parse_openvas_xml(xml_content: str) -> list[dict]:
    """
    Parse OpenVAS XML report into a list of structured finding dicts.

    Args:
        xml_content: Raw XML string from OpenVAS.

    Returns:
        List of dicts, each representing a vulnerability finding.
    """
    if not xml_content or not xml_content.strip():
        logger.warning("Empty XML content received")
        return []

    # Reject XML reports larger than 50 MB before attempting to parse them.
    # An XML bomb (billion-laughs attack) uses deeply nested entity references
    # to expand a small document into gigabytes in memory at parse time.
    # Rejecting oversized input here prevents that from exhausting server RAM.
    xml_size_limit = 50_000_000  # 50 MB
    if len(xml_content) > xml_size_limit:
        raise ValueError(
            f'XML report size ({len(xml_content):,} bytes) exceeds the '
            f'safe processing limit of {xml_size_limit:,} bytes.'
        )

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        logger.error(f"Failed to parse OpenVAS XML: {e}")
        return []

    findings = []
    results = root.findall('.//result')

    if not results:
        # Try alternate paths
        results = root.findall('.//results/result')

    logger.info(f"Parsing {len(results)} results from OpenVAS XML report")

    for result in results:
        threat = _find_text(result, 'threat', 'Log')
        severity = _map_threat_to_severity(threat)

        # Skip 'Log' severity findings (informational only)
        if severity == 'Log':
            continue

        finding = {
            'name': _find_text(result, 'name', 'Unknown Vulnerability'),
            'cve_ids': _extract_cves(result),
            'cvss_score': _extract_cvss(result),
            'severity': severity,
            'description': _find_text(result, 'description'),
            'host': _find_text(result, 'host'),
            'port': _find_text(result, 'port'),
            'solution': _find_text(result, 'solution') or _find_text(result, './/solution'),
            'references': _extract_references(result),
            'nvt_oid': result.find('.//nvt').get('oid', '') if result.find('.//nvt') is not None else '',
            'qod': _extract_qod(result),
        }
        findings.append(finding)

    logger.info(f"Parsed {len(findings)} actionable findings (excluding Log severity)")
    return findings
