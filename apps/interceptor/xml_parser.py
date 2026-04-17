"""
OpenVAS XML Report Parser.

Parses the XML output from GVM/OpenVAS into structured Python dicts.
Uses defusedxml to prevent XXE attacks.
"""
import logging
from typing import Optional

import defusedxml.ElementTree as ET

logger = logging.getLogger(__name__)


def _find_text(element, path: str, default: str = '') -> str:
    """Safely extract text from an XML element."""
    el = element.find(path)
    if el is not None and el.text:
        return el.text.strip()
    return default


def _extract_cves(result_element) -> list[str]:
    """Extract CVE IDs from a result's NVT refs."""
    cves = []
    for ref in result_element.findall('.//nvt/refs/ref'):
        if ref.get('type') == 'cve':
            cve_id = ref.get('id', '')
            if cve_id:
                cves.append(cve_id)
    return cves


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


def _extract_qod(result_element) -> Optional[int]:
    """Extract Quality of Detection value."""
    text = _find_text(result_element, './/qod/value')
    if text:
        try:
            return int(text)
        except ValueError:
            pass
    return None


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
