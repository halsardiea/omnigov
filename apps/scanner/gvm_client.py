# ---
# LOCATION : apps/scanner/gvm_client.py
# PURPOSE  : Abstracts all communication with the GVM/OpenVAS vulnerability scanner
#            behind a common interface. Two implementations are provided:
#              MockGVMClient — returns synthetic scan data; used when GVM_USE_MOCK=True
#                              so the full pipeline can be tested without a real scanner
#              RealGVMClient  — connects to the live GVM daemon via Unix socket or TLS;
#                              used in all real deployment scenarios
#            get_gvm_client() reads the GVM_USE_MOCK setting and returns the right one.
#
# CONNECTS TO:
#   - apps/scanner/tasks.py          → _run_scan_pipeline() calls get_gvm_client() to
#                                       obtain a client, then connect/create/poll/report
#   - omnigov/settings/base.py       → GVM_USE_MOCK, GVM_SOCKET_PATH, GVM_HOST,
#                                       GVM_PORT, GVM_ADMIN_USER, GVM_ADMIN_PASSWORD
#                                       are all read from settings here
# ---
"""
GVM Client — Wrapper around python-gvm for OpenVAS operations.

In development mode (GVM_USE_MOCK=True), returns simulated scan data
so the full pipeline can be tested without a running GVM instance.
"""
import logging
import time
import uuid
from typing import Optional

from django.conf import settings

logger = logging.getLogger(__name__)


# Normalises the scan config name submitted by the user into the hyphenated
# lowercase form that GVM scan profile keys expect.
# Handles both 'full_and_fast' (form choice value) and 'full-and-fast' (GVM name).
def _normalize_scan_config(scan_config: Optional[str]) -> str:
  normalized = (scan_config or 'full-and-fast').strip().lower().replace('_', '-')
  return normalized or 'full-and-fast'

# Sample OpenVAS XML report for mock/demo mode
MOCK_REPORT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<report id="mock-report-001" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"
        content_type="text/xml">
  <results max="100" start="1">
    <result id="res-001">
      <name>SSL/TLS: Certificate Expired</name>
      <host>192.168.1.10</host>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103955">
        <type>nvt</type>
        <name>SSL/TLS: Certificate Expired</name>
        <cvss_base>5.0</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2024-0001"/>
        </refs>
      </nvt>
      <threat>Medium</threat>
      <severity>5.0</severity>
      <qod><value>80</value></qod>
      <description>The SSL/TLS certificate on the remote host has expired. An attacker could exploit this to perform man-in-the-middle attacks. Certificate CN: server.local, Expired: 2024-01-15, Issuer: CN=Internal CA, Admin email: admin@company.com, Password hint: P@ssw0rd</description>
      <solution>Replace the expired SSL/TLS certificate with a valid one issued by a trusted Certificate Authority.</solution>
    </result>
    <result id="res-002">
      <name>SSH Weak Key Exchange Algorithms</name>
      <host>192.168.1.10</host>
      <port>22/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.150713">
        <type>nvt</type>
        <name>SSH Weak Key Exchange Algorithms</name>
        <cvss_base>4.3</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2023-48795"/>
        </refs>
      </nvt>
      <threat>Medium</threat>
      <severity>4.3</severity>
      <qod><value>70</value></qod>
      <description>The SSH server on host 192.168.1.10 supports weak key exchange algorithms: diffie-hellman-group-exchange-sha1, diffie-hellman-group14-sha1. Username: root, Password: toor123</description>
      <solution>Disable weak key exchange algorithms in the SSH server configuration. Edit /etc/ssh/sshd_config and set KexAlgorithms to only include strong algorithms.</solution>
    </result>
    <result id="res-003">
      <name>Apache HTTP Server Version Disclosed</name>
      <host>192.168.1.20</host>
      <port>80/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.900236">
        <type>nvt</type>
        <name>Apache HTTP Server Version Disclosed</name>
        <cvss_base>5.3</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2023-43622"/>
          <ref type="cve" id="CVE-2023-45802"/>
        </refs>
      </nvt>
      <threat>Medium</threat>
      <severity>5.3</severity>
      <qod><value>90</value></qod>
      <description>The remote Apache HTTP Server (httpd) version 2.4.49 is affected by multiple vulnerabilities. Server admin: webmaster@internal.corp</description>
      <solution>Update Apache HTTP Server to the latest stable version. Apply security patches from the Apache Software Foundation.</solution>
    </result>
    <result id="res-004">
      <name>SMB Signing Not Required</name>
      <host>192.168.1.30</host>
      <port>445/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.802726">
        <type>nvt</type>
        <name>SMB Signing Not Required</name>
        <cvss_base>6.5</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2007-5944"/>
        </refs>
      </nvt>
      <threat>High</threat>
      <severity>6.5</severity>
      <qod><value>95</value></qod>
      <description>SMB signing is not required on the remote Windows host WORKSTATION-PC (IP: 192.168.1.30, MAC: AA:BB:CC:DD:EE:FF). An attacker can exploit this to conduct man-in-the-middle attacks against the SMB connection. Domain: CORP.LOCAL, User: svc_backup</description>
      <solution>Enable SMB signing on all Windows hosts. Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always) = Enabled.</solution>
    </result>
    <result id="res-005">
      <name>TLS Version 1.0 and 1.1 Enabled</name>
      <host>192.168.1.20</host>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.117274">
        <type>nvt</type>
        <name>TLS Version 1.0 and 1.1 Enabled</name>
        <cvss_base>4.3</cvss_base>
        <refs>
          <ref type="url" id="https://www.ietf.org/rfc/rfc8996"/>
        </refs>
      </nvt>
      <threat>Medium</threat>
      <severity>4.3</severity>
      <qod><value>80</value></qod>
      <description>The remote service on 192.168.1.20:443 accepts connections using TLS 1.0 and TLS 1.1 which are considered cryptographically weak.</description>
      <solution>Disable TLS 1.0 and TLS 1.1. Configure the server to only support TLS 1.2 and TLS 1.3.</solution>
    </result>
    <result id="res-006">
      <name>Missing HTTP Strict Transport Security Header</name>
      <host>192.168.1.20</host>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.112081">
        <type>nvt</type>
        <name>Missing HTTP Strict Transport Security Header</name>
        <cvss_base>3.1</cvss_base>
        <refs/>
      </nvt>
      <threat>Low</threat>
      <severity>3.1</severity>
      <qod><value>80</value></qod>
      <description>The remote web server on 192.168.1.20 does not send the HTTP Strict-Transport-Security header.</description>
      <solution>Add the Strict-Transport-Security header to the web server configuration with an appropriate max-age value (e.g., max-age=31536000; includeSubDomains).</solution>
    </result>
    <result id="res-007">
      <name>Default Password on Admin Portal</name>
      <host>192.168.1.40</host>
      <port>8080/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.108234">
        <type>nvt</type>
        <name>Default/Weak Credentials Detected</name>
        <cvss_base>9.8</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2024-99999"/>
        </refs>
      </nvt>
      <threat>High</threat>
      <severity>9.8</severity>
      <qod><value>99</value></qod>
      <description>The admin portal at 192.168.1.40:8080 uses default credentials. Username: admin, Password: admin123. The attacker can gain full control of the application.</description>
      <solution>Change the default credentials immediately. Implement strong password policies and multi-factor authentication for administrative access.</solution>
    </result>
  </results>
</report>"""


class MockGVMClient:
    """Simulates GVM operations for development/testing without a running GVM instance."""

    def __init__(self):
        self._connected = False
        self._tasks = {}

    def connect(self):
        logger.info("[MOCK GVM] Connected to simulated GVM instance")
        self._connected = True

    def disconnect(self):
        self._connected = False

    def create_target(self, name: str, hosts: str) -> str:
        target_id = str(uuid.uuid4())
        logger.info(f"[MOCK GVM] Created target '{name}' ({hosts}) → {target_id}")
        return target_id

    def create_and_start_task(self, target_id: str, scan_config: str = 'full-and-fast') -> str:
        normalized_config = _normalize_scan_config(scan_config)
        task_id = str(uuid.uuid4())
        self._tasks[task_id] = {'progress': 0, 'status': 'Running', 'scan_config': normalized_config}
        logger.info(
            f"[MOCK GVM] Created and started task {task_id} for target {target_id} "
            f"with profile {normalized_config}"
        )
        return task_id

    def get_task_progress(self, task_id: str) -> int:
        if task_id not in self._tasks:
            return 100
        current = self._tasks[task_id]['progress']
        # Simulate progress increment (15-25% per poll)
        increment = min(100 - current, max(15, 25))
        self._tasks[task_id]['progress'] = min(100, current + increment)
        return self._tasks[task_id]['progress']

    def get_task_status(self, task_id: str) -> str:
        if task_id not in self._tasks:
            return 'Done'
        progress = self._tasks[task_id].get('progress', 0)
        status = self._tasks[task_id].get('status', 'Running')
        if status == 'Stopped':
            return 'Stopped'
        return 'Done' if progress >= 100 else 'Running'

    def stop_task(self, task_id: str) -> bool:
        if task_id in self._tasks:
            self._tasks[task_id]['status'] = 'Stopped'
        logger.info(f"[MOCK GVM] Stopped task {task_id}")
        return True

    def get_report(self, task_id: str) -> str:
        logger.info(f"[MOCK GVM] Returning mock XML report for task {task_id}")
        return MOCK_REPORT_XML

    def delete_task(self, task_id: str) -> bool:
        self._tasks.pop(task_id, None)
        return True


class RealGVMClient:
    """Connects to a real GVM/OpenVAS instance via GMP over TCP."""

    # Scan config UUIDs — queried live from this GVM installation
    SCAN_CONFIGS = {
        'full-and-fast':          'daba56c8-73ec-11df-a475-002264764cea',  # Full and fast
        'full-and-fast-ultimate': 'daba56c8-73ec-11df-a475-002264764cea',  # fallback → Full and fast
        'full-and-deep':          'daba56c8-73ec-11df-a475-002264764cea',  # fallback → Full and fast
        'full-and-deep-ultimate': 'daba56c8-73ec-11df-a475-002264764cea',  # fallback → Full and fast
        'discovery':              '8715c877-47a0-438d-98a3-27c7a6ab2196',  # Discovery
        'host-discovery':         '2d3f051c-55ba-11e3-bf43-406186ea4fc5',  # Host Discovery
        'system-discovery':       'bbca7412-a950-11e3-9109-406186ea4fc5',  # System Discovery
        'log4shell':              'e3efebc5-fc0d-4cb6-b1b4-55309d0a89f6',  # Log4Shell
    }
    DEFAULT_SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'

    def __init__(self):
        self._gmp = None  #GMPv225 instance with all GMP methods

    def connect(self):
        import os
        from gvm.protocols.gmp._gmp225 import GMPv225
        from gvm.transforms import EtreeCheckCommandTransform

        transform = EtreeCheckCommandTransform()
        socket_path = settings.GVM_SOCKET_PATH

        if socket_path and os.path.exists(socket_path):
            from gvm.connections import UnixSocketConnection
            connection = UnixSocketConnection(path=socket_path, timeout=60)
            logger.info(f"Connecting to GVM via Unix socket: {socket_path}")
        else:
            from gvm.connections import TLSConnection
            connection = TLSConnection(
                hostname=settings.GVM_HOST,
                port=settings.GVM_PORT,
                timeout=30,
            )
            logger.info(f"Connecting to GVM via TLS at {settings.GVM_HOST}:{settings.GVM_PORT}")

        # Directly instantiate GMPv225 — skips version negotiation that
        # rejects GMP 22.7. GMPv225 is backward-compatible with 22.7.
        self._gmp = GMPv225(connection=connection, transform=transform)
        self._gmp.connect()
        self._gmp.authenticate(settings.GVM_ADMIN_USER, settings.GVM_ADMIN_PASSWORD)
        logger.info("GVM authenticated successfully")

    def disconnect(self):
        if self._gmp:
            self._gmp.disconnect()
            self._gmp = None

    # "All IANA assigned TCP" port list — standard GVM default
    DEFAULT_PORT_LIST_ID = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'

    def create_target(self, name: str, hosts: str) -> str:
        response = self._gmp.create_target(
            name=name,
            hosts=[hosts],
            port_list_id=self.DEFAULT_PORT_LIST_ID,
            comment=f"OmniGov scan target: {hosts}",
        )
        target_id = response.get('id')
        logger.info(f"GVM target created: {target_id}")
        return target_id

    def create_and_start_task(self, target_id: str, scan_config: str = 'full-and-fast') -> str:
        normalized_config = _normalize_scan_config(scan_config)
        config_id = self.SCAN_CONFIGS.get(normalized_config, self.SCAN_CONFIGS['full-and-fast'])
        response = self._gmp.create_task(
            name=f"OmniGov Scan {target_id[:8]}",
            config_id=config_id,
            target_id=target_id,
            scanner_id=self.DEFAULT_SCANNER_ID,
            comment="Initiated by OmniGov platform",
        )
        task_id = response.get('id')
        self._gmp.start_task(task_id)
        logger.info(f"GVM task created and started: {task_id} using profile {normalized_config}")
        return task_id

    def get_task_progress(self, task_id: str) -> int:
        response = self._gmp.get_task(task_id)
        progress_el = response.find('.//progress')
        if progress_el is not None and progress_el.text:
            try:
                return int(progress_el.text)
            except ValueError:
                pass
        status = response.find('.//status')
        if status is not None and status.text == 'Done':
            return 100
        return 0

    def get_task_status(self, task_id: str) -> str:
        response = self._gmp.get_task(task_id)
        status = response.find('.//status')
        return status.text if status is not None else 'Unknown'

    def stop_task(self, task_id: str) -> bool:
        self._gmp.stop_task(task_id)
        logger.info(f"GVM task stopped: {task_id}")
        return True

    def get_report(self, task_id: str) -> str:
        import time as _time
        # GVM may not populate last_report immediately after status=Done
        for attempt in range(12):  # up to ~60 seconds
            task_resp = self._gmp.get_task(task_id)
            report_el = task_resp.find('.//last_report/report')
            if report_el is not None:
                break
            logger.warning(f"Report not ready for task {task_id}, attempt {attempt + 1}/12")
            _time.sleep(5)
        else:
            raise ValueError(f"No report found for task {task_id} after 60s")
        report_id = report_el.get('id')
        logger.info(f"Found report {report_id} for task {task_id}")

        # XML format ID
        xml_format_id = 'a994b278-1f62-11e1-96ac-406186ea4fc5'
        from lxml import etree
        report_resp = self._gmp.get_report(
            report_id,
            report_format_id=xml_format_id,
            ignore_pagination=True,
            details=True,
            filter_string="rows=-1 first=1",
        )
        return etree.tostring(report_resp, encoding='unicode')

    def delete_task(self, task_id: str) -> bool:
        self._gmp.delete_task(task_id)
        return True


def get_gvm_client():
    """Factory function — returns Mock or Real GVM client based on settings."""
    if settings.GVM_USE_MOCK:
        return MockGVMClient()
    return RealGVMClient()
