"""
Tests for the OpenVAS XML parser.
"""
import pytest
from apps.interceptor.xml_parser import parse_openvas_xml


SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<report>
  <results>
    <result>
      <name>SSL/TLS: Certificate Expired</name>
      <host>192.168.1.10</host>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103955">
        <cvss_base>5.0</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2024-0001"/>
          <ref type="url" id="https://example.com/advisory"/>
        </refs>
      </nvt>
      <threat>Medium</threat>
      <severity>5.0</severity>
      <qod><value>80</value></qod>
      <description>Expired SSL certificate found.</description>
      <solution>Replace with a valid certificate.</solution>
    </result>
    <result>
      <name>SSH Weak Algorithms</name>
      <host>10.0.0.5</host>
      <port>22/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.105611">
        <cvss_base>7.5</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2023-4567"/>
        </refs>
      </nvt>
      <threat>High</threat>
      <severity>7.5</severity>
      <qod><value>90</value></qod>
      <description>Weak SSH algorithms detected.</description>
      <solution>Disable weak ciphers.</solution>
    </result>
    <result>
      <name>Information Disclosure</name>
      <host>10.0.0.5</host>
      <port>80/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.999999">
        <cvss_base>0.0</cvss_base>
        <refs/>
      </nvt>
      <threat>Log</threat>
      <severity>0.0</severity>
      <description>Server version disclosed.</description>
      <solution/>
    </result>
  </results>
</report>"""


class TestOpenVASXMLParser:
    def test_parses_findings(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        # Should skip 'Log' severity
        assert len(findings) == 2

    def test_extracts_name(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        names = [f['name'] for f in findings]
        assert 'SSL/TLS: Certificate Expired' in names
        assert 'SSH Weak Algorithms' in names

    def test_extracts_cves(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        ssl_finding = next(f for f in findings if 'SSL' in f['name'])
        assert 'CVE-2024-0001' in ssl_finding['cve_ids']

    def test_extracts_cvss(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        ssh_finding = next(f for f in findings if 'SSH' in f['name'])
        assert ssh_finding['cvss_score'] == 7.5

    def test_maps_severity(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        ssl_finding = next(f for f in findings if 'SSL' in f['name'])
        ssh_finding = next(f for f in findings if 'SSH' in f['name'])
        assert ssl_finding['severity'] == 'Medium'
        assert ssh_finding['severity'] == 'High'

    def test_extracts_host_port(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        ssl_finding = next(f for f in findings if 'SSL' in f['name'])
        assert ssl_finding['host'] == '192.168.1.10'
        assert ssl_finding['port'] == '443/tcp'

    def test_extracts_qod(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        ssl_finding = next(f for f in findings if 'SSL' in f['name'])
        assert ssl_finding['qod'] == 80

    def test_extracts_references(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        ssl_finding = next(f for f in findings if 'SSL' in f['name'])
        assert any('example.com' in r for r in ssl_finding['references'])
        assert any('nvd.nist.gov' in r for r in ssl_finding['references'])

    def test_skips_log_severity(self):
        findings = parse_openvas_xml(SAMPLE_XML)
        names = [f['name'] for f in findings]
        assert 'Information Disclosure' not in names

    def test_empty_xml(self):
        assert parse_openvas_xml("") == []
        assert parse_openvas_xml("   ") == []

    def test_invalid_xml(self):
        assert parse_openvas_xml("<not-valid>xml") == []

    def test_no_results(self):
        xml = '<?xml version="1.0"?><report><results></results></report>'
        assert parse_openvas_xml(xml) == []
