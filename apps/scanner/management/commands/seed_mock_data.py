"""
Management command: seed_mock_data

Creates a set of realistic, fully-analysed scans with findings, framework
correlation, and generated reports (executive PDF + technical PDF + CSV).
Leaves any existing scan on 192.168.56.* (Metasploitable) untouched.

Usage:
    python manage.py seed_mock_data
    python manage.py seed_mock_data --flush   # wipe mock scans before re-seeding
"""
import logging
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)

# ── Realistic vulnerability library ─────────────────────────────────────────
# Each entry becomes one TechnicalFinding row.  Fields mirror the model exactly.
FINDINGS_LIBRARY = [
    # ── Critical ────────────────────────────────────────────────────────────
    {
        'name': 'OpenSSL Remote Code Execution (CVE-2022-0778)',
        'severity': 'Critical',
        'cvss_score': 9.8,
        'cve_ids': ['CVE-2022-0778'],
        'port': '443/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.117605',
        'qod': 90,
        'description': (
            'An infinite loop in the BN_mod_sqrt() function of OpenSSL allows a remote '
            'attacker to trigger a denial-of-service condition by sending a specially '
            'crafted certificate. Versions prior to 1.0.2zd, 1.1.1n and 3.0.2 are affected.'
        ),
        'solution': (
            'Upgrade OpenSSL to 1.0.2zd, 1.1.1n, or 3.0.2+. Rotate any TLS certificates '
            'that were issued by a potentially compromised CA chain.'
        ),
        'references': ['https://www.openssl.org/news/secadv/20220315.txt', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0778'],
    },
    {
        'name': 'Apache HTTP Server Path Traversal and RCE (CVE-2021-41773)',
        'severity': 'Critical',
        'cvss_score': 9.8,
        'cve_ids': ['CVE-2021-41773', 'CVE-2021-42013'],
        'port': '80/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.117508',
        'qod': 95,
        'description': (
            'A path traversal vulnerability in Apache HTTP Server 2.4.49 allows an '
            'unauthenticated remote attacker to access files outside the document root, '
            'including /etc/passwd, and execute arbitrary code if mod_cgi is enabled.'
        ),
        'solution': (
            'Upgrade to Apache HTTP Server 2.4.51 or later. Disable mod_cgi if not required. '
            'Ensure "require all denied" is set in the default directory configuration.'
        ),
        'references': ['https://httpd.apache.org/security/vulnerabilities_24.html', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
    },
    {
        'name': 'SMB Remote Code Execution — EternalBlue (MS17-010)',
        'severity': 'Critical',
        'cvss_score': 9.3,
        'cve_ids': ['CVE-2017-0144', 'CVE-2017-0145'],
        'port': '445/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.108214',
        'qod': 97,
        'description': (
            'The SMBv1 protocol implementation in Microsoft Windows contains a buffer '
            'overflow that allows unauthenticated attackers to execute arbitrary code '
            'remotely. This vulnerability was exploited by WannaCry and NotPetya ransomware.'
        ),
        'solution': (
            'Apply Microsoft Security Bulletin MS17-010 immediately. Disable SMBv1 via '
            'PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. '
            'Block TCP/445 at the network perimeter.'
        ),
        'references': ['https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010', 'https://nvd.nist.gov/vuln/detail/CVE-2017-0144'],
    },
    {
        'name': 'Log4Shell Remote Code Execution (CVE-2021-44228)',
        'severity': 'Critical',
        'cvss_score': 10.0,
        'cve_ids': ['CVE-2021-44228', 'CVE-2021-45046'],
        'port': '8080/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.117592',
        'qod': 95,
        'description': (
            'Apache Log4j2 JNDI lookup feature allows attackers to execute arbitrary code '
            'by sending a specially crafted string that triggers a JNDI lookup to an '
            'attacker-controlled LDAP server. Affects Log4j 2.0-beta9 through 2.14.1.'
        ),
        'solution': (
            'Upgrade Log4j2 to 2.17.1+ (Java 8), 2.12.4+ (Java 7), or 2.3.2+ (Java 6). '
            'As a temporary mitigation, set -Dlog4j2.formatMsgNoLookups=true. '
            'Remove the JndiLookup class from all Log4j2 jars on the classpath.'
        ),
        'references': ['https://logging.apache.org/log4j/2.x/security.html', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
    },

    # ── High ─────────────────────────────────────────────────────────────────
    {
        'name': 'OpenSSH Username Enumeration (CVE-2018-15919)',
        'severity': 'High',
        'cvss_score': 7.5,
        'cve_ids': ['CVE-2018-15919'],
        'port': '22/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.141271',
        'qod': 80,
        'description': (
            'OpenSSH through 7.8 allows remote attackers to enumerate user accounts by '
            'observing the timing differences in authentication responses. This information '
            'can be used to launch targeted brute-force attacks.'
        ),
        'solution': (
            'Upgrade OpenSSH to 7.9 or later. Implement account lockout policies and '
            'rate-limiting on SSH authentication attempts. Consider deploying '
            'fail2ban or equivalent intrusion prevention.'
        ),
        'references': ['https://www.openwall.com/lists/oss-security/2018/08/24/2', 'https://nvd.nist.gov/vuln/detail/CVE-2018-15919'],
    },
    {
        'name': 'SSL/TLS BEAST Attack Vulnerability',
        'severity': 'High',
        'cvss_score': 7.4,
        'cve_ids': ['CVE-2011-3389'],
        'port': '443/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.103025',
        'qod': 85,
        'description': (
            'The server supports TLS 1.0 with CBC-mode cipher suites, making it vulnerable '
            'to the BEAST (Browser Exploit Against SSL/TLS) attack. An attacker on the '
            'network path can decrypt HTTPS traffic by exploiting a predictable IV.'
        ),
        'solution': (
            'Disable TLS 1.0 and TLS 1.1. Enable TLS 1.2 and TLS 1.3 only. Prioritise '
            'AEAD cipher suites (AES-GCM, ChaCha20-Poly1305). Apply HSTS with a '
            'minimum age of 31536000 seconds.'
        ),
        'references': ['https://vnhacker.blogspot.com/2011/09/beast.html', 'https://nvd.nist.gov/vuln/detail/CVE-2011-3389'],
    },
    {
        'name': 'Anonymous FTP Access Enabled',
        'severity': 'High',
        'cvss_score': 7.5,
        'cve_ids': [],
        'port': '21/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.10081',
        'qod': 99,
        'description': (
            'The FTP server allows anonymous read access. Unauthenticated users can browse '
            'and download files from the server without providing credentials, potentially '
            'exposing sensitive configuration, backup, or user data.'
        ),
        'solution': (
            'Disable anonymous FTP access entirely. If file sharing is required, replace '
            'FTP with SFTP (SSH file transfer) or FTPS, and require strong authentication. '
            'Audit files accessible via the current anonymous share.'
        ),
        'references': ['https://www.ietf.org/rfc/rfc0959.txt'],
    },
    {
        'name': 'Default Credentials — Tomcat Manager Interface',
        'severity': 'High',
        'cvss_score': 8.8,
        'cve_ids': [],
        'port': '8080/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.103722',
        'qod': 99,
        'description': (
            'The Apache Tomcat Manager application is accessible with factory-default '
            'credentials (admin:admin or tomcat:tomcat). An attacker with network access '
            'can upload a malicious WAR file and achieve remote code execution.'
        ),
        'solution': (
            'Change all default Tomcat Manager credentials immediately. Restrict access '
            'to the /manager and /host-manager paths to trusted IP addresses only via the '
            'RemoteAddrValve. Remove the manager application entirely if not needed.'
        ),
        'references': ['https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html'],
    },
    {
        'name': 'MS-RDP Remote Desktop Bluekeep (CVE-2019-0708)',
        'severity': 'High',
        'cvss_score': 9.8,
        'cve_ids': ['CVE-2019-0708'],
        'port': '3389/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.107529',
        'qod': 90,
        'description': (
            'A remote code execution vulnerability in Remote Desktop Services allows an '
            'unauthenticated attacker to connect via RDP and execute arbitrary code. '
            'Affects Windows XP, 7, Server 2003, and Server 2008 R2.'
        ),
        'solution': (
            'Apply the Microsoft security patch (KB4499175). Enable Network Level '
            'Authentication (NLA). Block RDP (TCP 3389) from the internet. '
            'Use a VPN or bastion host for all remote access.'
        ),
        'references': ['https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708', 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708'],
    },
    {
        'name': 'Weak SSH MAC Algorithm Enabled (MD5/96-bit)',
        'severity': 'High',
        'cvss_score': 7.4,
        'cve_ids': [],
        'port': '22/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.105610',
        'qod': 70,
        'description': (
            'The SSH server advertises and accepts weak message authentication codes '
            '(hmac-md5, hmac-md5-96, hmac-sha1-96). These algorithms have known weaknesses '
            'that can allow a privileged attacker to forge or modify SSH packets.'
        ),
        'solution': (
            'Edit /etc/ssh/sshd_config and add: MACs hmac-sha2-512,hmac-sha2-256. '
            'Restart the SSH service. Verify with: ssh -vv host 2>&1 | grep MAC'
        ),
        'references': ['https://www.ssh.com/academy/ssh/protocol'],
    },

    # ── Medium ───────────────────────────────────────────────────────────────
    {
        'name': 'HTTP Security Headers Missing — HSTS, X-Frame-Options',
        'severity': 'Medium',
        'cvss_score': 5.3,
        'cve_ids': [],
        'port': '80/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.112138',
        'qod': 70,
        'description': (
            'The web server does not set Strict-Transport-Security, X-Frame-Options, '
            'or Content-Security-Policy response headers. This exposes users to clickjacking, '
            'mixed-content attacks, and HTTPS downgrade vulnerabilities.'
        ),
        'solution': (
            'Add the following headers to every HTTPS response:\n'
            'Strict-Transport-Security: max-age=31536000; includeSubDomains\n'
            'X-Frame-Options: DENY\n'
            'Content-Security-Policy: default-src \'self\'\n'
            'X-Content-Type-Options: nosniff'
        ),
        'references': ['https://owasp.org/www-project-secure-headers/', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
    },
    {
        'name': 'SSL Certificate Signed with SHA-1',
        'severity': 'Medium',
        'cvss_score': 5.9,
        'cve_ids': [],
        'port': '443/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.103441',
        'qod': 80,
        'description': (
            'The TLS certificate presented by this server was signed using the SHA-1 '
            'algorithm. SHA-1 is cryptographically broken and modern browsers may display '
            'a security warning or refuse the connection.'
        ),
        'solution': (
            'Reissue the certificate using SHA-256 or stronger (SHA-384, SHA-512). '
            'Contact your Certificate Authority to obtain a replacement certificate. '
            'Verify the new certificate chain before revoking the old one.'
        ),
        'references': ['https://shattered.io/', 'https://cabforum.org/working-groups/server/baseline-requirements/'],
    },
    {
        'name': 'PHP expose_php Directive Enabled',
        'severity': 'Medium',
        'cvss_score': 5.0,
        'cve_ids': [],
        'port': '80/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.10316',
        'qod': 75,
        'description': (
            'The PHP installation exposes the exact version string in X-Powered-By '
            'response headers (e.g. PHP/7.4.3). This allows attackers to identify '
            'the software stack and target known version-specific vulnerabilities.'
        ),
        'solution': (
            'Set expose_php = Off in php.ini and restart the web server. '
            'Also remove or set server_tokens Off / ServerSignature Off '
            'to suppress web server version disclosure.'
        ),
        'references': ['https://www.php.net/manual/en/security.general.php'],
    },
    {
        'name': 'SNMP v1/v2c Community String — Default "public"',
        'severity': 'Medium',
        'cvss_score': 6.5,
        'cve_ids': [],
        'port': '161/udp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.10264',
        'qod': 99,
        'description': (
            'The SNMP service is accepting connections with the default community string '
            '"public". This grants read access to the full MIB tree, exposing network '
            'topology, interface statistics, ARP tables, and routing information.'
        ),
        'solution': (
            'Change the SNMP community string to a long, random value. '
            'Upgrade to SNMPv3 with authentication and encryption. '
            'Restrict SNMP access via ACL to authorised management stations only. '
            'Block UDP/161 at the perimeter firewall.'
        ),
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-1999-0517'],
    },
    {
        'name': 'NTP Amplification Vulnerability',
        'severity': 'Medium',
        'cvss_score': 5.0,
        'cve_ids': ['CVE-2013-5211'],
        'port': '123/udp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.104000',
        'qod': 80,
        'description': (
            'The NTP server responds to monlist requests, allowing attackers to use this '
            'server as an amplifier in distributed denial-of-service attacks. A single '
            'forged request can trigger responses up to 556x the request size.'
        ),
        'solution': (
            'Upgrade ntpd to 4.2.7p26 or later. Disable the monlist command by adding '
            '"restrict default kod nomodify notrap nopeer noquery" to ntp.conf. '
            'Block inbound UDP/123 from untrusted sources.'
        ),
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2013-5211'],
    },
    {
        'name': 'Outdated WordPress Core — Multiple Known CVEs',
        'severity': 'Medium',
        'cvss_score': 6.1,
        'cve_ids': ['CVE-2022-21661', 'CVE-2022-21662'],
        'port': '80/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.141231',
        'qod': 85,
        'description': (
            'WordPress 5.7.x is installed and is not running the latest version. '
            'Known vulnerabilities include a SQL injection via WP_Query and an '
            'authenticated XSS in the editor component.'
        ),
        'solution': (
            'Update WordPress Core to the latest stable release via the WordPress admin '
            'dashboard. Enable automatic minor updates. Review and update all plugins and '
            'themes. Back up files and the database before updating.'
        ),
        'references': ['https://wordpress.org/news/category/security/', 'https://nvd.nist.gov/vuln/detail/CVE-2022-21661'],
    },
    {
        'name': 'MySQL Remote Access with Root Credentials',
        'severity': 'Medium',
        'cvss_score': 6.5,
        'cve_ids': [],
        'port': '3306/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.108079',
        'qod': 90,
        'description': (
            'The MySQL server is accessible remotely and accepts connections as the root '
            'database user. Direct root access to MySQL from the network significantly '
            'increases the risk of data exfiltration or database destruction.'
        ),
        'solution': (
            'Revoke remote root login: DELETE FROM mysql.user WHERE User="root" AND '
            'Host != "localhost"; FLUSH PRIVILEGES. Create dedicated application accounts '
            'with the minimum necessary privileges. Bind MySQL to 127.0.0.1 if remote '
            'access is not required.'
        ),
        'references': ['https://dev.mysql.com/doc/refman/8.0/en/security-against-attack.html'],
    },

    # ── Low ──────────────────────────────────────────────────────────────────
    {
        'name': 'ICMP Timestamp Reply Information Disclosure',
        'severity': 'Low',
        'cvss_score': 2.6,
        'cve_ids': ['CVE-1999-0524'],
        'port': 'icmp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.11367',
        'qod': 70,
        'description': (
            'The host responds to ICMP timestamp requests, revealing the system clock. '
            'This information can be used by attackers to bypass time-based security '
            'controls or to fingerprint the operating system.'
        ),
        'solution': (
            'Block ICMP type 13 (Timestamp Request) at the perimeter firewall. '
            'On Linux, add: iptables -A INPUT -p icmp --icmp-type timestamp-request -j DROP. '
            'On Windows, disable via Windows Firewall advanced rules.'
        ),
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-1999-0524'],
    },
    {
        'name': 'SSH Server Version Disclosure',
        'severity': 'Low',
        'cvss_score': 2.6,
        'cve_ids': [],
        'port': '22/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.10882',
        'qod': 70,
        'description': (
            'The SSH server banner exposes the exact version of OpenSSH installed '
            '(e.g. OpenSSH_7.4p1). This allows attackers to identify and target '
            'known version-specific vulnerabilities without authentication.'
        ),
        'solution': (
            'While the version cannot be fully hidden from authenticated session banners, '
            'set "DebianBanner no" and use a custom version string in sshd_config. '
            'Ensure the software is fully patched regardless of banner obfuscation.'
        ),
        'references': [],
    },
    {
        'name': 'TCP Timestamps Enabled',
        'severity': 'Low',
        'cvss_score': 2.6,
        'cve_ids': ['CVE-1999-0531'],
        'port': 'general/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.80091',
        'qod': 80,
        'description': (
            'The remote host has TCP timestamps enabled. This allows an attacker to '
            'estimate the system uptime and can be used for OS fingerprinting, '
            'which may assist in identifying vulnerabilities specific to that OS version.'
        ),
        'solution': (
            'On Linux: sysctl -w net.ipv4.tcp_timestamps=0 and add to /etc/sysctl.conf. '
            'On Windows: netsh int tcp set global timestamps=disabled. '
            'Impact is low — address after higher-severity findings are remediated.'
        ),
        'references': [],
    },
    {
        'name': 'Web Server Directory Listing Enabled',
        'severity': 'Low',
        'cvss_score': 5.0,
        'cve_ids': [],
        'port': '80/tcp',
        'nvt_oid': '1.3.6.1.4.1.25623.1.0.10678',
        'qod': 80,
        'description': (
            'The web server is configured to list directory contents when no index file '
            'is present. This exposes the file structure and potentially sensitive files '
            'such as configuration, backup, or source code files.'
        ),
        'solution': (
            'Disable directory listing in Apache by removing or replacing the "Options Indexes" '
            'directive with "Options -Indexes" in the server or virtual host configuration. '
            'In Nginx, remove the "autoindex on" directive.'
        ),
        'references': ['https://owasp.org/www-project-web-security-testing-guide/'],
    },
]


# ── Scan scenarios ───────────────────────────────────────────────────────────
# Each describes one realistic scan job. Finding indices reference FINDINGS_LIBRARY.
SCAN_SCENARIOS = [
    {
        'name': 'Q1 2026 — Internal Network Security Assessment',
        'target': '10.0.1.0/24',
        'scan_config': 'full_and_fast',
        'frameworks': ['CIS Controls', 'NIST Cybersecurity Framework'],
        'finding_indices': [0, 1, 4, 5, 7, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21],
        'days_ago': 12,
    },
    {
        'name': 'Finance Server — Pre-Audit Vulnerability Sweep',
        'target': '10.0.2.50',
        'scan_config': 'full_and_fast',
        'frameworks': ['ISO/IEC 27001 Annex A Controls'],
        'finding_indices': [2, 3, 5, 7, 8, 9, 11, 13, 14, 15, 16, 17, 18],
        'days_ago': 7,
    },
    {
        'name': 'DMZ Web Tier — OWASP Application Assessment',
        'target': '172.16.5.20',
        'scan_config': 'full_and_fast',
        'frameworks': ['OWASP Top 10', 'CIS Controls'],
        'finding_indices': [1, 3, 6, 10, 11, 12, 14, 15, 16, 19, 20, 21],
        'days_ago': 5,
    },
    {
        'name': 'HR Portal — Regulatory Compliance Check',
        'target': '10.0.3.100',
        'scan_config': 'full_and_fast',
        'frameworks': ['Jordan National Cybersecurity Framework', 'ISO/IEC 27001 Annex A Controls'],
        'finding_indices': [4, 5, 7, 9, 10, 11, 12, 13, 15, 17, 18, 20, 21],
        'days_ago': 3,
    },
    {
        'name': 'Backup Infrastructure — Patch Verification Scan',
        'target': '10.10.0.1',
        'scan_config': 'full_and_fast',
        'frameworks': ['NIST Cybersecurity Framework', 'CIS Controls'],
        'finding_indices': [0, 2, 4, 6, 8, 9, 10, 13, 15, 16, 17, 18, 19, 20, 21],
        'days_ago': 1,
    },
]


class Command(BaseCommand):
    help = 'Seed realistic mock scan data (scans, findings, reports). Preserves Metasploitable scan.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--flush',
            action='store_true',
            help='Delete previously seeded mock scans before creating new ones.',
        )

    def handle(self, *args, **options):
        from apps.scanner.models import ScanTask, ApprovedTargetRange
        from apps.interceptor.models import TechnicalFinding, FindingAnalysis
        from apps.compliance.models import Framework
        from apps.reports.tasks import generate_reports_pipeline
        from apps.interceptor.correlation import correlate_finding

        User = get_user_model()

        self.stdout.write(self.style.MIGRATE_HEADING('\n── OmniGov Mock Data Seeder ──────────────────────────────────────'))

        # Get or create the admin user
        admin = User.objects.filter(is_superuser=True).first()
        if not admin:
            self.stderr.write('No superuser found. Run: python manage.py createsuperuser first.')
            return
        self.stdout.write(f'  Using admin account: {admin.email}')

        # Optionally flush previous mock scans (never touch Metasploitable)
        if options['flush']:
            mock_scans = ScanTask.objects.filter(target__in=[s['target'] for s in SCAN_SCENARIOS])
            count = mock_scans.count()
            mock_scans.delete()
            self.stdout.write(self.style.WARNING(f'  Flushed {count} existing mock scans.'))

        # Ensure all mock target ranges are approved
        self._ensure_approved_ranges(ApprovedTargetRange, admin)

        # Load all frameworks into a lookup dict
        framework_map = {f.name: f for f in Framework.objects.all()}
        if not framework_map:
            self.stderr.write('No frameworks found. Run: python manage.py load_compliance_fixtures first.')
            return
        self.stdout.write(f'  Frameworks available: {", ".join(framework_map.keys())}')

        # Get the first framework as the FK (legacy required field)
        default_framework = next(iter(framework_map.values()))

        created_count = 0
        for scenario in SCAN_SCENARIOS:
            scan_name = scenario['name']

            # Skip if already exists
            if ScanTask.objects.filter(name=scan_name).exists():
                self.stdout.write(f'  Skipping (already exists): {scan_name}')
                continue

            self.stdout.write(f'\n  Creating: {scan_name}')

            # Resolve framework objects for this scenario
            scenario_frameworks = [
                framework_map[name]
                for name in scenario['frameworks']
                if name in framework_map
            ]
            if not scenario_frameworks:
                self.stdout.write(self.style.WARNING(f'    No matching frameworks found, skipping.'))
                continue

            # Build timestamps
            created = timezone.now() - timedelta(days=scenario['days_ago'], hours=2)
            started = created + timedelta(minutes=3)
            completed = started + timedelta(minutes=25)

            # Create the ScanTask
            scan = ScanTask.objects.create(
                name=scan_name,
                target=scenario['target'],
                scan_config=scenario['scan_config'],
                framework=scenario_frameworks[0],
                status=ScanTask.Status.ANALYZED,
                progress=100,
                created_by=admin,
                started_at=started,
                completed_at=completed,
                created_at=created,
            )
            scan.selected_frameworks.set(scenario_frameworks)

            self.stdout.write(f'    ScanTask #{scan.pk} created')

            # Create findings for this scan
            finding_defs = [FINDINGS_LIBRARY[i] for i in scenario['finding_indices'] if i < len(FINDINGS_LIBRARY)]
            findings_created = []

            for fdef in finding_defs:
                finding = TechnicalFinding.objects.create(
                    scan_task=scan,
                    name=fdef['name'],
                    severity=fdef['severity'],
                    cvss_score=fdef['cvss_score'],
                    cve_ids=fdef['cve_ids'],
                    host=scenario['target'].split('/')[0],
                    port=fdef.get('port', ''),
                    description=fdef['description'],
                    solution=fdef['solution'],
                    references=fdef.get('references', []),
                    nvt_oid=fdef.get('nvt_oid', ''),
                    qod=fdef.get('qod'),
                )
                findings_created.append(finding)

            self.stdout.write(f'    Created {len(findings_created)} findings')

            # Run correlation for each finding × each framework
            for framework in scenario_frameworks:
                controls = list(framework.controls.all())
                for finding in findings_created:
                    result = correlate_finding(finding, framework, controls=controls)
                    if not hasattr(finding, '_analysis_created'):
                        FindingAnalysis.objects.update_or_create(
                            technical_finding=finding,
                            defaults={
                                'matched_controls': result.get('matched_controls', []),
                                'executive_summary': result.get('executive_summary', ''),
                                'technical_remediation': result.get('technical_remediation', ''),
                                'analysis_method': result.get('analysis_method', 'heuristic'),
                                'confidence_score': result.get('confidence_score'),
                                'raw_provider_response': result.get('raw_provider_response', {}),
                            },
                        )
                        finding._analysis_created = True

            self.stdout.write(f'    Correlation complete')

            # Generate actual PDF + CSV reports
            try:
                generate_reports_pipeline(scan.pk)
                report_count = scan.reports.count()
                self.stdout.write(self.style.SUCCESS(f'    Reports generated: {report_count}'))
            except Exception as exc:
                self.stdout.write(self.style.WARNING(f'    Report generation failed: {exc}'))

            created_count += 1

        self.stdout.write(self.style.SUCCESS(f'\n── Done. {created_count} scans seeded. ─────────────────────────────\n'))

    def _ensure_approved_ranges(self, ApprovedTargetRange, admin):
        ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        for cidr in ranges:
            ApprovedTargetRange.objects.get_or_create(
                cidr=cidr,
                defaults={'description': 'RFC 1918 private range — seeded', 'created_by': admin},
            )
        self.stdout.write(f'  Approved target ranges: {", ".join(ranges)}')
