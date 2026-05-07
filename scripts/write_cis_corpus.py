"""Regenerates data/corpus/cis_controls_v8_1.json with all 153 CIS Controls v8.1 safeguards."""
import json
import sys
from pathlib import Path

CORPUS_FILE = Path(__file__).resolve().parents[1] / "data" / "corpus" / "cis_controls_v8_1.json"

FRAMEWORK = {
    "name": "CIS Controls",
    "version": "v8.1",
    "description": "CIS Controls v8.1 — 18 top-level Controls broken into 153 Safeguards prioritised by Implementation Group (IG1/IG2/IG3). Source: Center for Internet Security.",
    "is_active": True,
    "source_url": "https://www.cisecurity.org/controls/cis-controls-list"
}

CONTROLS = [
    # ── CIS Control 1: Inventory and Control of Enterprise Assets ──────────────
    {
        "control_id": "CIS 1.1",
        "title": "Establish and Maintain Detailed Enterprise Asset Inventory",
        "category": "CIS Control 1 – Inventory and Control of Enterprise Assets",
        "description": "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, including end-user devices, network devices, non-computing/IoT devices, and servers.",
        "keywords": ["asset inventory", "hardware inventory", "enterprise asset", "device tracking", "IG1"],
        "guidance": "Review and update the inventory of all enterprise assets bi-annually, or more frequently. Integrate automated discovery and CMDB tools to maintain accuracy."
    },
    {
        "control_id": "CIS 1.2",
        "title": "Address Unauthorized Assets",
        "category": "CIS Control 1 – Inventory and Control of Enterprise Assets",
        "description": "Ensure that a process exists to address unauthorized assets on a weekly basis. The enterprise may choose to remove the asset from the network, deny the asset from connecting remotely to the network, or quarantine the asset.",
        "keywords": ["unauthorized device", "rogue device", "network quarantine", "IG1"],
        "guidance": "Implement DHCP-based tracking and network admission controls to detect and respond to unauthorized devices quickly."
    },
    {
        "control_id": "CIS 1.3",
        "title": "Utilize an Active Discovery Tool",
        "category": "CIS Control 1 – Inventory and Control of Enterprise Assets",
        "description": "Utilize an active discovery tool to identify assets connected to the enterprise's network. Configure the active discovery tool to execute daily, or more frequently.",
        "keywords": ["active discovery", "network scan", "asset discovery", "IG2"],
        "guidance": "Deploy credentialed or agent-based scanners to enumerate all active hosts; reconcile results against the authoritative inventory."
    },
    {
        "control_id": "CIS 1.4",
        "title": "Use DHCP Logging to Update Enterprise Asset Inventory",
        "category": "CIS Control 1 – Inventory and Control of Enterprise Assets",
        "description": "Use Dynamic Host Configuration Protocol (DHCP) logging on all DHCP servers or IP address management tools to update the enterprise's asset inventory. Review and use logs to update the asset inventory weekly, or more frequently.",
        "keywords": ["DHCP", "IP address management", "IPAM", "IG2"],
        "guidance": "Export DHCP leases and reconcile them with the enterprise asset register to catch unmanaged or transient devices."
    },
    {
        "control_id": "CIS 1.5",
        "title": "Use a Passive Asset Discovery Tool",
        "category": "CIS Control 1 – Inventory and Control of Enterprise Assets",
        "description": "Use a passive discovery tool to identify assets connected to the enterprise's network. Review and use scans to update the asset inventory at least weekly, or more frequently.",
        "keywords": ["passive discovery", "network traffic analysis", "asset detection", "IG3"],
        "guidance": "Supplement active scanning with passive network tap or span-port analysis to identify assets that may evade active probes."
    },
    # ── CIS Control 2: Inventory and Control of Software Assets ───────────────
    {
        "control_id": "CIS 2.1",
        "title": "Establish and Maintain a Software Inventory",
        "category": "CIS Control 2 – Inventory and Control of Software Assets",
        "description": "Establish and maintain a detailed inventory of all licensed software installed on enterprise assets. The software inventory must document the title, publisher, initial install/use date, and business purpose for each entry.",
        "keywords": ["software inventory", "application catalog", "licensed software", "IG1"],
        "guidance": "Collect software inventory from endpoint management tools and review it monthly to remove unlicensed or unused software."
    },
    {
        "control_id": "CIS 2.2",
        "title": "Ensure Authorized Software is Currently Supported",
        "category": "CIS Control 2 – Inventory and Control of Software Assets",
        "description": "Ensure that only currently supported software is designated as authorized in the software inventory for enterprise assets. If software is unsupported yet necessary for operations, document an exception detailing mitigating controls and planned upgrade.",
        "keywords": ["unsupported software", "end-of-life", "software support", "IG1"],
        "guidance": "Flag EOL software in the inventory; obtain vendor support extensions or isolate EOL systems until replaced."
    },
    {
        "control_id": "CIS 2.3",
        "title": "Address Unauthorized Software",
        "category": "CIS Control 2 – Inventory and Control of Software Assets",
        "description": "Ensure that unauthorized software is either removed from use on enterprise assets or receives a documented exception. Review monthly, or more frequently.",
        "keywords": ["unauthorized software", "software removal", "shadow IT", "IG1"],
        "guidance": "Define a process for employees to report newly installed software; remediate unauthorized installations within an SLA."
    },
    {
        "control_id": "CIS 2.4",
        "title": "Utilize Automated Software Inventory Tools",
        "category": "CIS Control 2 – Inventory and Control of Software Assets",
        "description": "Utilize software inventory tools, when possible, throughout the enterprise to automate the discovery and documentation of installed software.",
        "keywords": ["software discovery", "endpoint management", "automated inventory", "IG2"],
        "guidance": "Deploy agents or integrate with SCCM/Intune/JAMF to continuously collect installed software data."
    },
    {
        "control_id": "CIS 2.5",
        "title": "Allowlist Authorized Software",
        "category": "CIS Control 2 – Inventory and Control of Software Assets",
        "description": "Use technical controls, such as application allowlisting, to ensure that only authorized software can execute or be accessed. Reassess bi-annually, or more frequently.",
        "keywords": ["application allowlist", "application whitelist", "execution control", "IG2"],
        "guidance": "Implement application control policies using AppLocker, Windows Defender Application Control, or equivalent, to block unapproved executables."
    },
    {
        "control_id": "CIS 2.6",
        "title": "Allowlist Authorized Libraries",
        "category": "CIS Control 2 – Inventory and Control of Software Assets",
        "description": "Use technical controls to ensure that only authorized software libraries, such as .dll, .ocx, .so files, are allowed to load into a system process. Block unauthorized libraries.",
        "keywords": ["library allowlist", "DLL control", "shared library", "IG2"],
        "guidance": "Maintain an approved library catalog and configure OS-level controls to prevent loading of unsigned or unlisted libraries."
    },
    {
        "control_id": "CIS 2.7",
        "title": "Allowlist Authorized Scripts",
        "category": "CIS Control 2 – Inventory and Control of Software Assets",
        "description": "Use technical controls, such as digital signatures and version controls, to ensure that only authorized scripts, such as .ps1, .py files, are allowed to execute. Block unauthorized scripts from executing.",
        "keywords": ["script allowlist", "PowerShell", "script signing", "IG3"],
        "guidance": "Require script signing policies and block unsigned script execution through AppLocker or PowerShell constrained language mode."
    },
    # ── CIS Control 3: Data Protection ────────────────────────────────────────
    {
        "control_id": "CIS 3.1",
        "title": "Establish and Maintain a Data Management Process",
        "category": "CIS Control 3 – Data Protection",
        "description": "Establish and maintain a data management process. Address data sensitivity, data owner, handling of data, data retention limits, and disposal requirements, based on sensitivity and retention standards for the enterprise.",
        "keywords": ["data management", "data governance", "data owner", "data policy", "IG1"],
        "guidance": "Document the lifecycle for each data class from creation through disposal, assign data owners, and review annually."
    },
    {
        "control_id": "CIS 3.2",
        "title": "Establish and Maintain a Data Inventory",
        "category": "CIS Control 3 – Data Protection",
        "description": "Establish and maintain a data inventory, based on the enterprise's data management process. Inventory sensitive data, at a minimum. Review and update inventory annually.",
        "keywords": ["data inventory", "data catalog", "sensitive data", "IG1"],
        "guidance": "Use data discovery tools to locate sensitive data stores; catalog location, owner, and classification for each data asset."
    },
    {
        "control_id": "CIS 3.3",
        "title": "Configure Data Access Control Lists",
        "category": "CIS Control 3 – Data Protection",
        "description": "Configure data access control lists based on a user's need to know. Apply data access control lists to local and remote file systems, databases, and applications.",
        "keywords": ["access control list", "ACL", "need to know", "file permissions", "IG1"],
        "guidance": "Enforce least-privilege access on file shares, databases, and cloud storage by regularly auditing and trimming unnecessary permissions."
    },
    {
        "control_id": "CIS 3.4",
        "title": "Enforce Data Retention",
        "category": "CIS Control 3 – Data Protection",
        "description": "Retain data according to the enterprise's data management process. Data retention must include both minimum and maximum timelines.",
        "keywords": ["data retention", "records retention", "data lifecycle", "IG1"],
        "guidance": "Implement automated retention policies in document management, email, and database systems; confirm alignment with legal obligations."
    },
    {
        "control_id": "CIS 3.5",
        "title": "Securely Dispose of Data",
        "category": "CIS Control 3 – Data Protection",
        "description": "Securely dispose of data as outlined in the enterprise's data management process. Ensure the disposal process and timeframe are compliant with applicable regulations.",
        "keywords": ["data disposal", "secure deletion", "data destruction", "IG1"],
        "guidance": "Use cryptographic erasure for cloud/virtual data and certified physical destruction for physical media."
    },
    {
        "control_id": "CIS 3.6",
        "title": "Encrypt Data on End-User Devices",
        "category": "CIS Control 3 – Data Protection",
        "description": "Encrypt data on end-user devices containing sensitive data. Example implementations include Windows BitLocker, Apple FileVault, Linux dm-crypt.",
        "keywords": ["full disk encryption", "device encryption", "BitLocker", "FileVault", "IG1"],
        "guidance": "Mandate full-disk encryption on all laptops and mobile devices; centrally manage recovery keys in an escrow solution."
    },
    {
        "control_id": "CIS 3.7",
        "title": "Establish and Maintain a Data Classification Scheme",
        "category": "CIS Control 3 – Data Protection",
        "description": "Establish and maintain an overall data classification scheme for the enterprise. Enterprises may use labels such as Sensitive, Confidential, and Public and classify data according to those labels.",
        "keywords": ["data classification", "data labeling", "sensitivity labels", "IG2"],
        "guidance": "Define a tiered classification taxonomy, provide automated labeling tooling, and train employees on correct classification."
    },
    {
        "control_id": "CIS 3.8",
        "title": "Document Data Flows",
        "category": "CIS Control 3 – Data Protection",
        "description": "Document data flows. Data flow documentation includes service provider data flows and should be based on the enterprise's data management process. Review and update documentation annually.",
        "keywords": ["data flow", "data flow diagram", "DFD", "IG2"],
        "guidance": "Map data flows between systems, third parties, and geographic regions; update maps when architectures change."
    },
    {
        "control_id": "CIS 3.9",
        "title": "Encrypt Data on Removable Media",
        "category": "CIS Control 3 – Data Protection",
        "description": "Encrypt data on removable media.",
        "keywords": ["removable media", "USB encryption", "portable storage", "IG2"],
        "guidance": "Enforce hardware or software encryption on USB drives; consider blocking unencrypted removable media via group policy."
    },
    {
        "control_id": "CIS 3.10",
        "title": "Encrypt Sensitive Data in Transit",
        "category": "CIS Control 3 – Data Protection",
        "description": "Encrypt sensitive data in transit. Example implementations include Transport Layer Security (TLS) and OpenSSH.",
        "keywords": ["TLS", "data in transit", "transport encryption", "SSH", "IG2"],
        "guidance": "Require TLS 1.2+ for all web and API traffic; enforce SSH for remote administration; disable weak ciphers."
    },
    {
        "control_id": "CIS 3.11",
        "title": "Encrypt Sensitive Data at Rest",
        "category": "CIS Control 3 – Data Protection",
        "description": "Encrypt sensitive data at rest on servers, applications, and databases containing sensitive data. Storage-layer encryption meets the minimum requirement of this Safeguard.",
        "keywords": ["encryption at rest", "database encryption", "server-side encryption", "IG2"],
        "guidance": "Enable transparent data encryption (TDE) on databases and server-side encryption on cloud object stores; manage keys in a dedicated KMS."
    },
    {
        "control_id": "CIS 3.12",
        "title": "Segment Data Processing and Storage Based on Sensitivity",
        "category": "CIS Control 3 – Data Protection",
        "description": "Segment data processing and storage based on the sensitivity of the data. Do not process sensitive data on enterprise assets intended for lower sensitivity data.",
        "keywords": ["data segmentation", "network segmentation", "data isolation", "IG2"],
        "guidance": "Place high-sensitivity workloads in dedicated VLANs or cloud security groups; enforce strict inter-zone traffic policies."
    },
    {
        "control_id": "CIS 3.13",
        "title": "Deploy a Data Loss Prevention Solution",
        "category": "CIS Control 3 – Data Protection",
        "description": "Implement an automated tool, such as a host-based Data Loss Prevention (DLP) tool to identify all sensitive data stored, processed, or transmitted through enterprise assets, and update the enterprise's sensitive data inventory.",
        "keywords": ["DLP", "data loss prevention", "data exfiltration", "IG2"],
        "guidance": "Deploy endpoint and network DLP policies tuned to sensitive data patterns (PII, PCI data, trade secrets); integrate alerts into the SIEM."
    },
    {
        "control_id": "CIS 3.14",
        "title": "Log Sensitive Data Access",
        "category": "CIS Control 3 – Data Protection",
        "description": "Log sensitive data access, including modification and disposal.",
        "keywords": ["data access logging", "audit trail", "sensitive data", "IG3"],
        "guidance": "Enable database audit logging and file system access auditing for sensitive data stores; ship logs to a centralized SIEM."
    },
    # ── CIS Control 4: Secure Configuration ───────────────────────────────────
    {
        "control_id": "CIS 4.1",
        "title": "Establish and Maintain a Secure Configuration Process",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Establish and maintain a secure configuration process for enterprise assets (end-user devices, network devices, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually.",
        "keywords": ["secure baseline", "configuration management", "hardening standard", "IG1"],
        "guidance": "Adopt industry benchmarks (CIS Benchmarks, DISA STIGs) as baselines; document deviations with compensating controls."
    },
    {
        "control_id": "CIS 4.2",
        "title": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Establish and maintain a secure configuration process for network devices. Review and update documentation annually.",
        "keywords": ["network hardening", "router configuration", "switch baseline", "IG1"],
        "guidance": "Apply CIS Benchmark hardening to all network devices; enforce configuration change control and periodic compliance scans."
    },
    {
        "control_id": "CIS 4.3",
        "title": "Configure Automatic Session Locking on Enterprise Assets",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Configure automatic session locking on enterprise assets after a defined period of inactivity. For general purpose operating systems, the period must not exceed 15 minutes. For mobile devices, the period must not exceed 2 minutes.",
        "keywords": ["screen lock", "session timeout", "inactivity lock", "IG1"],
        "guidance": "Enforce session-lock policies via Group Policy or MDM; set 15-minute timeout for workstations and 2-minute for mobile."
    },
    {
        "control_id": "CIS 4.4",
        "title": "Implement and Manage a Firewall on Servers",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent.",
        "keywords": ["host firewall", "server hardening", "firewall rules", "IG1"],
        "guidance": "Enable host-based firewall on all servers; define allow-lists of required ports and block all others by default."
    },
    {
        "control_id": "CIS 4.5",
        "title": "Implement and Manage a Firewall on End-User Devices",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Implement and manage a host-based firewall or port-filtering tool on end-user devices, with a default-deny rule that drops all traffic except those services and ports that are explicitly allowed.",
        "keywords": ["endpoint firewall", "desktop firewall", "default deny", "IG1"],
        "guidance": "Deploy endpoint firewall policies through MDM or Group Policy; enforce default-deny stance and log blocked connections."
    },
    {
        "control_id": "CIS 4.6",
        "title": "Securely Manage Enterprise Assets and Software",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Securely manage enterprise assets and software. Example implementations include managing configuration through version-controlled infrastructure-as-code and accessing administrative interfaces over SSH and HTTPS. Do not use insecure protocols such as Telnet and HTTP unless operationally essential.",
        "keywords": ["secure management", "SSH", "HTTPS", "Telnet", "infrastructure as code", "IG2"],
        "guidance": "Replace Telnet/HTTP management with SSH/HTTPS; store configuration in version-controlled repositories with change approval."
    },
    {
        "control_id": "CIS 4.7",
        "title": "Manage Default Accounts on Enterprise Assets and Software",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Manage default accounts on enterprise assets and software, such as root, administrator, and other pre-configured vendor accounts. Example implementations can include disabling default accounts or making them unusable.",
        "keywords": ["default accounts", "default password", "vendor accounts", "IG1"],
        "guidance": "Rename or disable vendor default accounts; change default credentials immediately upon deployment; audit quarterly."
    },
    {
        "control_id": "CIS 4.8",
        "title": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
        "category": "CIS Control 4 – Secure Configuration of Enterprise Assets and Software",
        "description": "Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function.",
        "keywords": ["unnecessary services", "attack surface reduction", "service hardening", "IG2"],
        "guidance": "Enumerate running services on each asset class and remove or disable any not required for the system's business purpose."
    },
    # ── CIS Control 5: Account Management ─────────────────────────────────────
    {
        "control_id": "CIS 5.1",
        "title": "Establish and Maintain an Inventory of Accounts",
        "category": "CIS Control 5 – Account Management",
        "description": "Establish and maintain an inventory of all accounts managed in the enterprise. The inventory must include both user and administrator accounts. Validate that all active accounts are authorized, on a recurring schedule at a minimum quarterly.",
        "keywords": ["account inventory", "user accounts", "account management", "IG1"],
        "guidance": "Maintain a directory-linked account inventory; review and recertify access quarterly, removing any accounts no longer needed."
    },
    {
        "control_id": "CIS 5.2",
        "title": "Use Unique Passwords",
        "category": "CIS Control 5 – Account Management",
        "description": "Use unique passwords for all enterprise assets. Best practice implementation includes at minimum an 8-character password for accounts using MFA and a 14-character password for accounts not using MFA.",
        "keywords": ["unique passwords", "password policy", "password length", "IG1"],
        "guidance": "Enforce minimum password length and complexity; deploy a password manager or SSO to prevent reuse across services."
    },
    {
        "control_id": "CIS 5.3",
        "title": "Disable Dormant Accounts",
        "category": "CIS Control 5 – Account Management",
        "description": "Delete or disable any dormant accounts after a period of 45 days of inactivity, where supported.",
        "keywords": ["dormant accounts", "inactive accounts", "account deprovisioning", "IG1"],
        "guidance": "Run monthly reports on accounts with no logins in 45 days; automatically disable them and notify the owner before deletion."
    },
    {
        "control_id": "CIS 5.4",
        "title": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
        "category": "CIS Control 5 – Account Management",
        "description": "Restrict administrator privileges to dedicated administrator accounts on enterprise assets. Conduct general computing activities, such as internet browsing and email, from the user's primary non-privileged account.",
        "keywords": ["admin accounts", "privileged access", "separation of duties", "IG1"],
        "guidance": "Require admin tasks to use dedicated admin accounts; enforce PAW (Privileged Access Workstations) for domain administrators."
    },
    {
        "control_id": "CIS 5.5",
        "title": "Establish and Maintain an Inventory of Service Accounts",
        "category": "CIS Control 5 – Account Management",
        "description": "Establish and maintain an inventory of service accounts. The inventory must include department owner, review date, and purpose. Perform service account reviews to validate that all active accounts are authorized, at a minimum quarterly.",
        "keywords": ["service accounts", "non-human accounts", "machine accounts", "IG2"],
        "guidance": "Document every service account with its owner and purpose; rotate service account credentials and review permissions quarterly."
    },
    {
        "control_id": "CIS 5.6",
        "title": "Centralize Account Management",
        "category": "CIS Control 5 – Account Management",
        "description": "Centralize account management through a directory or identity service.",
        "keywords": ["centralized IAM", "directory service", "Active Directory", "LDAP", "IG2"],
        "guidance": "Consolidate all accounts into a central identity provider; eliminate local accounts where the central provider can serve the role."
    },
    # ── CIS Control 6: Access Control Management ───────────────────────────────
    {
        "control_id": "CIS 6.1",
        "title": "Establish an Access Granting Process",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Establish and follow a process, preferably automated, for granting access to enterprise assets upon new hire, rights grant, or role change of a user.",
        "keywords": ["access provisioning", "joiner process", "access granting", "IG1"],
        "guidance": "Define a formal access request and approval workflow; automate provisioning through an IAM platform tied to HR systems."
    },
    {
        "control_id": "CIS 6.2",
        "title": "Establish an Access Revoking Process",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Establish and follow a process, preferably automated, for revoking access to enterprise assets, through disability of accounts immediately upon termination, rights revocation, or role change of a user.",
        "keywords": ["access revocation", "leaver process", "deprovisioning", "IG1"],
        "guidance": "Automate account disabling within hours of termination or role change; revoke all elevated privileges as the first step."
    },
    {
        "control_id": "CIS 6.3",
        "title": "Require MFA for Externally-Exposed Applications",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Require all externally-exposed enterprise or third-party applications to enforce MFA, where supported. Enforcing MFA through a directory service or SSO provider is a satisfactory implementation of this Safeguard.",
        "keywords": ["MFA", "multi-factor authentication", "externally exposed", "internet-facing", "IG1"],
        "guidance": "Enforce MFA on all internet-facing logins via SSO or application-level configuration; monitor for bypass attempts."
    },
    {
        "control_id": "CIS 6.4",
        "title": "Require MFA for Remote Network Access",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Require MFA for remote network access.",
        "keywords": ["MFA", "VPN", "remote access", "IG1"],
        "guidance": "Require MFA on VPN, RDP gateways, and remote-access solutions; consider phishing-resistant MFA (FIDO2) for privileged access."
    },
    {
        "control_id": "CIS 6.5",
        "title": "Require MFA for Administrative Access",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Require MFA for all administrative access accounts, where supported, on all enterprise assets, whether managed on-site or through a third-party provider.",
        "keywords": ["MFA", "admin accounts", "privileged access", "IG2"],
        "guidance": "Enforce step-up authentication for admin actions; use hardware tokens or FIDO2 for the highest-privilege roles."
    },
    {
        "control_id": "CIS 6.6",
        "title": "Establish and Maintain an Inventory of Authentication and Authorization Systems",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Establish and maintain an inventory of the enterprise's authentication and authorization systems, including those hosted on-site or at a remote service provider. Review the inventory at a minimum annually.",
        "keywords": ["authentication systems", "authorization systems", "IAM inventory", "IG2"],
        "guidance": "Document all identity providers, SSO systems, PAM tools, and MFA vendors; validate configurations against policy annually."
    },
    {
        "control_id": "CIS 6.7",
        "title": "Centralize Access Control",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Centralize access control for all enterprise assets through a directory service or SSO provider, where supported.",
        "keywords": ["centralized access control", "SSO", "identity federation", "IG2"],
        "guidance": "Federate application access through a central IdP; eliminate standalone local accounts by integrating every system with SSO."
    },
    {
        "control_id": "CIS 6.8",
        "title": "Define and Maintain Role-Based Access Control",
        "category": "CIS Control 6 – Access Control Management",
        "description": "Define and maintain role-based access control, through determining and documenting the access rights necessary for each role within the enterprise. Perform access control reviews of enterprise assets to validate that all privileges are authorized, at a minimum once every 6 months.",
        "keywords": ["RBAC", "role-based access control", "access review", "least privilege", "IG3"],
        "guidance": "Define job-function-based roles with minimum necessary permissions; recertify role assignments semi-annually."
    },
    # ── CIS Control 7: Continuous Vulnerability Management ────────────────────
    {
        "control_id": "CIS 7.1",
        "title": "Establish and Maintain a Vulnerability Management Process",
        "category": "CIS Control 7 – Continuous Vulnerability Management",
        "description": "Establish and maintain a documented vulnerability management process for enterprise assets. Review and update documentation annually.",
        "keywords": ["vulnerability management", "vulnerability program", "patch management", "IG1"],
        "guidance": "Define scan frequency, severity thresholds, remediation SLAs, and exception handling; align with risk appetite."
    },
    {
        "control_id": "CIS 7.2",
        "title": "Establish and Maintain a Remediation Process",
        "category": "CIS Control 7 – Continuous Vulnerability Management",
        "description": "Establish and maintain a risk-based remediation strategy documented in a remediation process, with monthly, or more frequent, reviews.",
        "keywords": ["remediation", "patch SLA", "vulnerability remediation", "IG1"],
        "guidance": "Assign severity-based remediation timelines (Critical: 24h, High: 7d, Medium: 30d); track open items in a VM platform."
    },
    {
        "control_id": "CIS 7.3",
        "title": "Perform Automated Operating System Patch Management",
        "category": "CIS Control 7 – Continuous Vulnerability Management",
        "description": "Perform operating system updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.",
        "keywords": ["OS patching", "automated patching", "patch management", "Windows Update", "IG1"],
        "guidance": "Configure WSUS, SCCM, or equivalent to deploy OS patches; verify patch compliance through vulnerability scans."
    },
    {
        "control_id": "CIS 7.4",
        "title": "Perform Automated Application Patch Management",
        "category": "CIS Control 7 – Continuous Vulnerability Management",
        "description": "Perform application updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.",
        "keywords": ["application patching", "automated patching", "software updates", "IG1"],
        "guidance": "Integrate application patch management into the WSUS/SCCM/MDM pipeline; include third-party applications."
    },
    {
        "control_id": "CIS 7.5",
        "title": "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
        "category": "CIS Control 7 – Continuous Vulnerability Management",
        "description": "Perform automated vulnerability scans of internal enterprise assets on a quarterly, or more frequent, basis. Conduct both authenticated and unauthenticated scans, using a SCAP-compliant vulnerability scanning tool.",
        "keywords": ["internal scan", "vulnerability scan", "authenticated scan", "SCAP", "IG2"],
        "guidance": "Schedule credentialed internal scans monthly; feed results into the vulnerability management platform."
    },
    {
        "control_id": "CIS 7.6",
        "title": "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
        "category": "CIS Control 7 – Continuous Vulnerability Management",
        "description": "Perform automated vulnerability scans of externally-exposed enterprise assets using a SCAP-compliant vulnerability scanning tool. Perform scans on a monthly, or more frequent, basis.",
        "keywords": ["external scan", "internet-facing", "external attack surface", "IG2"],
        "guidance": "Conduct external scans from an outside perspective monthly; consider continuous external attack surface monitoring tools."
    },
    {
        "control_id": "CIS 7.7",
        "title": "Remediate Detected Vulnerabilities",
        "category": "CIS Control 7 – Continuous Vulnerability Management",
        "description": "Remediate detected vulnerabilities in software through processes and tooling on a monthly, or more frequent, basis, based on the remediation process.",
        "keywords": ["vulnerability remediation", "patch deployment", "risk-based remediation", "IG2"],
        "guidance": "Prioritize remediation by CVSS score and active exploitation status; validate fixes with rescans within the SLA window."
    },
    # ── CIS Control 8: Audit Log Management ───────────────────────────────────
    {
        "control_id": "CIS 8.1",
        "title": "Establish and Maintain an Audit Log Management Process",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Establish and maintain an audit log management process that defines the enterprise's logging requirements. At a minimum, address the collection, review, and retention of audit logs for enterprise assets.",
        "keywords": ["audit log policy", "log management", "logging requirements", "IG1"],
        "guidance": "Document what to log, where to store logs, how long to retain them, and who reviews them; align with regulatory requirements."
    },
    {
        "control_id": "CIS 8.2",
        "title": "Collect Audit Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Collect audit logs. Ensure that logging, per the enterprise's audit log management process, has been enabled across enterprise assets.",
        "keywords": ["log collection", "event logs", "audit logs", "IG1"],
        "guidance": "Enable security event logging on all enterprise assets; verify logging is active on every system after each configuration change."
    },
    {
        "control_id": "CIS 8.3",
        "title": "Ensure Adequate Audit Log Storage",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Ensure that logging destinations maintain adequate storage to comply with the enterprise's audit log management process.",
        "keywords": ["log storage", "log retention", "storage capacity", "IG1"],
        "guidance": "Size log storage to retain the required minimum period; configure alerts for storage capacity thresholds to prevent log loss."
    },
    {
        "control_id": "CIS 8.4",
        "title": "Standardize Time Synchronization",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Standardize time synchronization. Configure at least two synchronized time sources across enterprise assets, where supported.",
        "keywords": ["NTP", "time synchronization", "time source", "log correlation", "IG2"],
        "guidance": "Deploy a hierarchical NTP infrastructure; enforce NTP configuration on all devices and verify log timestamp consistency."
    },
    {
        "control_id": "CIS 8.5",
        "title": "Collect Detailed Audit Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Configure detailed audit logging for enterprise assets containing sensitive data. Include event source, date, username, timestamp, source addresses, destination addresses, and other useful elements that could assist in a forensic investigation.",
        "keywords": ["detailed logging", "forensic logging", "sensitive data logging", "IG2"],
        "guidance": "Enable verbose audit logging on systems containing sensitive data; ensure log fields capture all context needed for investigation."
    },
    {
        "control_id": "CIS 8.6",
        "title": "Collect DNS Query Audit Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Collect DNS query audit logs on enterprise assets, where appropriate and supported.",
        "keywords": ["DNS logging", "DNS query logs", "domain resolution", "IG2"],
        "guidance": "Enable DNS query logging on enterprise resolvers and forward logs to SIEM; use for threat hunting and C2 detection."
    },
    {
        "control_id": "CIS 8.7",
        "title": "Collect URL Request Audit Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Collect URL request audit logs for enterprise assets, where appropriate and supported.",
        "keywords": ["web proxy logs", "URL logging", "HTTP logs", "IG2"],
        "guidance": "Deploy a web proxy or DNS filtering service with full URL logging; ship logs to SIEM for correlation."
    },
    {
        "control_id": "CIS 8.8",
        "title": "Collect Command-Line Audit Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Collect command-line audit logs. Example implementations include collecting audit logs from PowerShell, BASH, and remote administrative sessions.",
        "keywords": ["command-line logging", "PowerShell logging", "bash history", "IG2"],
        "guidance": "Enable PowerShell Script Block Logging and module logging; configure bash to log history to syslog; forward to SIEM."
    },
    {
        "control_id": "CIS 8.9",
        "title": "Centralize Audit Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Centralize, to the extent possible, audit log collection and retention across enterprise assets.",
        "keywords": ["SIEM", "centralized logging", "log aggregation", "IG2"],
        "guidance": "Deploy a SIEM and ship all endpoint, network, and application logs to it; normalize event formats for correlation."
    },
    {
        "control_id": "CIS 8.10",
        "title": "Retain Audit Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Retain audit logs across enterprise assets for a minimum of 90 days.",
        "keywords": ["log retention", "90 days", "audit trail", "IG2"],
        "guidance": "Configure log retention for at least 90 days online and 1 year in archive; verify retention policies after system changes."
    },
    {
        "control_id": "CIS 8.11",
        "title": "Conduct Audit Log Reviews",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Conduct reviews of audit logs to detect anomalies or abnormal events that could indicate a potential threat. Conduct reviews on a weekly, or more frequent, basis.",
        "keywords": ["log review", "anomaly detection", "SIEM alerts", "IG2"],
        "guidance": "Establish automated SIEM correlation rules and analyst review workflows; define escalation procedures for high-priority alerts."
    },
    {
        "control_id": "CIS 8.12",
        "title": "Collect Service Provider Logs",
        "category": "CIS Control 8 – Audit Log Management",
        "description": "Collect service provider logs, where supported. Example implementations include collecting authentication and authorization events, data creation and disposal events, and user management events.",
        "keywords": ["cloud logs", "SaaS logs", "service provider logs", "IG3"],
        "guidance": "Configure log export from SaaS/IaaS providers (AWS CloudTrail, Azure Monitor) and ingest into SIEM for unified visibility."
    },
    # ── CIS Control 9: Email and Web Browser Protections ──────────────────────
    {
        "control_id": "CIS 9.1",
        "title": "Ensure Use of Only Fully Supported Browsers and Email Clients",
        "category": "CIS Control 9 – Email and Web Browser Protections",
        "description": "Ensure only fully supported browsers and email clients are allowed to execute in the enterprise, only using the latest version of browsers and email clients provided through the vendor.",
        "keywords": ["browser updates", "email client", "supported software", "IG1"],
        "guidance": "Allowlist only enterprise-approved, current-version browsers; use MDM to enforce automatic updates."
    },
    {
        "control_id": "CIS 9.2",
        "title": "Use DNS Filtering Services",
        "category": "CIS Control 9 – Email and Web Browser Protections",
        "description": "Use DNS filtering services on all enterprise assets to block access to known malicious domains.",
        "keywords": ["DNS filtering", "DNS sinkhole", "malicious domain blocking", "IG1"],
        "guidance": "Configure enterprise DNS resolvers to use a filtering service; enforce for remote workers via VPN."
    },
    {
        "control_id": "CIS 9.3",
        "title": "Maintain and Enforce Network-Based URL Filters",
        "category": "CIS Control 9 – Email and Web Browser Protections",
        "description": "Enforce and update network-based URL filters to limit an enterprise asset's ability to connect to potentially malicious or unapproved websites. Enforce filters for all enterprise assets.",
        "keywords": ["URL filtering", "web proxy", "category filtering", "IG2"],
        "guidance": "Deploy a proxy or CASB with category and reputation-based URL filtering; review block-list and category policies monthly."
    },
    {
        "control_id": "CIS 9.4",
        "title": "Restrict Unnecessary or Unauthorized Browser and Email Client Extensions",
        "category": "CIS Control 9 – Email and Web Browser Protections",
        "description": "Restrict, either through uninstalling or disabling, any unauthorized or unnecessary browser or email client plugins, extensions, and add-on applications.",
        "keywords": ["browser extensions", "plugins", "add-ons", "IG2"],
        "guidance": "Allowlist browser extensions via group policy or MDM; periodically audit installed extensions and remove unapproved ones."
    },
    {
        "control_id": "CIS 9.5",
        "title": "Implement DMARC",
        "category": "CIS Control 9 – Email and Web Browser Protections",
        "description": "To lower the chance of spoofed or modified emails from valid domains, implement DMARC policy and verification, starting with implementing the Sender Policy Framework (SPF) and DomainKeys Identified Mail (DKIM) standards.",
        "keywords": ["DMARC", "SPF", "DKIM", "email spoofing", "IG2"],
        "guidance": "Publish SPF, DKIM, and DMARC DNS records for all sending domains; begin in monitoring mode then enforce p=quarantine or p=reject."
    },
    {
        "control_id": "CIS 9.6",
        "title": "Block Unnecessary File Types",
        "category": "CIS Control 9 – Email and Web Browser Protections",
        "description": "Block unnecessary file types attempting to enter the enterprise's email gateway.",
        "keywords": ["file type blocking", "email gateway", "attachment filtering", "IG2"],
        "guidance": "Configure the email gateway to block high-risk attachment types (exe, vbs, js, iso); allow only business-essential file types."
    },
    {
        "control_id": "CIS 9.7",
        "title": "Deploy and Maintain Email Server Anti-Malware Protections",
        "category": "CIS Control 9 – Email and Web Browser Protections",
        "description": "Deploy and maintain email server anti-malware protections, such as attachment scanning and/or sandboxing.",
        "keywords": ["email anti-malware", "email sandbox", "attachment scanning", "IG2"],
        "guidance": "Enable anti-malware scanning and sandboxing at the email gateway layer; integrate threat intelligence feeds."
    },
    # ── CIS Control 10: Malware Defenses ──────────────────────────────────────
    {
        "control_id": "CIS 10.1",
        "title": "Deploy and Maintain Anti-Malware Software",
        "category": "CIS Control 10 – Malware Defenses",
        "description": "Deploy and maintain anti-malware software on all enterprise assets.",
        "keywords": ["anti-malware", "antivirus", "endpoint protection", "IG1"],
        "guidance": "Deploy EDR or AV on all endpoints and servers; ensure agents are active, communicating, and not excluded from high-risk paths."
    },
    {
        "control_id": "CIS 10.2",
        "title": "Configure Automatic Anti-Malware Signature Updates",
        "category": "CIS Control 10 – Malware Defenses",
        "description": "Configure automatic updates for anti-malware signature files on all enterprise assets.",
        "keywords": ["signature updates", "anti-malware updates", "definition files", "IG1"],
        "guidance": "Enforce automatic signature updates at least daily; alert on endpoints with signatures older than 24 hours."
    },
    {
        "control_id": "CIS 10.3",
        "title": "Disable Autorun and Autoplay for Removable Media",
        "category": "CIS Control 10 – Malware Defenses",
        "description": "Disable autorun and autoplay auto-execute functionality for removable media.",
        "keywords": ["autorun", "autoplay", "removable media", "USB", "IG1"],
        "guidance": "Disable AutoRun and AutoPlay via Group Policy on all Windows endpoints; enforce equivalent settings on macOS/Linux."
    },
    {
        "control_id": "CIS 10.4",
        "title": "Configure Automatic Anti-Malware Scanning of Removable Media",
        "category": "CIS Control 10 – Malware Defenses",
        "description": "Configure anti-malware software to automatically scan removable media.",
        "keywords": ["removable media scanning", "USB scan", "anti-malware scan", "IG1"],
        "guidance": "Configure anti-malware to trigger an on-insert scan for all removable media; block media that fails the scan."
    },
    {
        "control_id": "CIS 10.5",
        "title": "Enable Anti-Exploitation Features",
        "category": "CIS Control 10 – Malware Defenses",
        "description": "Enable anti-exploitation features on enterprise assets and software, where possible, such as Microsoft Data Execution Prevention (DEP), Windows Defender Exploit Guard, or Apple System Integrity Protection (SIP) and Gatekeeper.",
        "keywords": ["DEP", "exploit protection", "ASLR", "Gatekeeper", "IG2"],
        "guidance": "Enable OS-level exploit mitigations (DEP, ASLR, CFG); use WDEG policies to apply additional mitigations for high-risk applications."
    },
    {
        "control_id": "CIS 10.6",
        "title": "Centrally Manage Anti-Malware Software",
        "category": "CIS Control 10 – Malware Defenses",
        "description": "Centrally manage anti-malware software.",
        "keywords": ["centralized AV management", "EDR console", "endpoint protection platform", "IG2"],
        "guidance": "Deploy all AV/EDR through a centralized console; use dashboards to track agent health, policy compliance, and alert volume."
    },
    {
        "control_id": "CIS 10.7",
        "title": "Use Behavior-Based Anti-Malware Software",
        "category": "CIS Control 10 – Malware Defenses",
        "description": "Use behavior-based anti-malware software.",
        "keywords": ["behavioral detection", "EDR", "heuristic detection", "IG3"],
        "guidance": "Deploy EDR solutions with behavioral analytics and ML-based detection in addition to signature-based scanning."
    },
    # ── CIS Control 11: Data Recovery ─────────────────────────────────────────
    {
        "control_id": "CIS 11.1",
        "title": "Establish and Maintain a Data Recovery Process",
        "category": "CIS Control 11 – Data Recovery",
        "description": "Establish and maintain a data recovery process. In the process, address the scope of data recovery activities, recovery prioritization, and the security of backup data. Review and update documentation annually.",
        "keywords": ["data recovery", "backup policy", "recovery plan", "IG1"],
        "guidance": "Document RPO/RTO targets; define priorities for which systems recover first; ensure backup procedures are tested."
    },
    {
        "control_id": "CIS 11.2",
        "title": "Perform Automated Backups",
        "category": "CIS Control 11 – Data Recovery",
        "description": "Perform automated backups of in-scope enterprise assets. Run backups weekly, or more frequently, based on the sensitivity of the data.",
        "keywords": ["automated backup", "backup schedule", "backup frequency", "IG1"],
        "guidance": "Configure automated daily backups for critical systems; verify backup jobs complete successfully through monitoring alerts."
    },
    {
        "control_id": "CIS 11.3",
        "title": "Protect Recovery Data",
        "category": "CIS Control 11 – Data Recovery",
        "description": "Protect recovery data with equivalent controls to the original data. Reference encryption or data separation, based on technology.",
        "keywords": ["backup protection", "backup encryption", "recovery data security", "IG1"],
        "guidance": "Encrypt backup data at rest and in transit; apply the same access controls to backup repositories as to production systems."
    },
    {
        "control_id": "CIS 11.4",
        "title": "Establish and Maintain an Isolated Instance of Recovery Data",
        "category": "CIS Control 11 – Data Recovery",
        "description": "Establish and maintain an isolated instance of recovery data. Example implementations include version controlling backup destinations through offline, cloud, or off-site systems or services.",
        "keywords": ["offsite backup", "backup isolation", "3-2-1 backup", "IG2"],
        "guidance": "Maintain a copy of backups in an air-gapped, immutable, or geographically separate location to resist ransomware."
    },
    {
        "control_id": "CIS 11.5",
        "title": "Test Data Recovery",
        "category": "CIS Control 11 – Data Recovery",
        "description": "Test backup recovery quarterly, or more frequently, for a sampling of in-scope enterprise assets.",
        "keywords": ["backup testing", "recovery test", "restore test", "IG2"],
        "guidance": "Schedule quarterly restore tests from backup; document results and close gaps before the next test cycle."
    },
    # ── CIS Control 12: Network Infrastructure Management ─────────────────────
    {
        "control_id": "CIS 12.1",
        "title": "Ensure Network Infrastructure is Up-to-Date",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Ensure network infrastructure is kept up-to-date. Example implementations include running the latest stable release of patches and versions on routers, firewalls, and switches.",
        "keywords": ["network patching", "firmware updates", "router updates", "IG2"],
        "guidance": "Track EOL status of all network infrastructure; apply security patches within defined SLAs."
    },
    {
        "control_id": "CIS 12.2",
        "title": "Establish and Maintain a Secure Network Architecture",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Establish and maintain a secure network architecture. A secure network architecture must address segmentation, least privilege, and availability, at a minimum.",
        "keywords": ["network architecture", "segmentation", "network design", "IG1"],
        "guidance": "Segment the network into security zones aligned with data classification; document and review the architecture annually."
    },
    {
        "control_id": "CIS 12.3",
        "title": "Securely Manage Network Infrastructure",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Securely manage network infrastructure. Example implementations include version control for all network device configuration and out-of-band management channels.",
        "keywords": ["network management", "out-of-band management", "version control", "IG2"],
        "guidance": "Use out-of-band management networks; store device configurations in version control with change approval workflows."
    },
    {
        "control_id": "CIS 12.4",
        "title": "Establish and Maintain Architecture Diagram(s)",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Establish and maintain architecture diagram(s) and/or other network system documentation. Review and update documentation annually.",
        "keywords": ["network diagram", "architecture documentation", "topology", "IG2"],
        "guidance": "Maintain up-to-date logical and physical network diagrams; update after any major change and review annually."
    },
    {
        "control_id": "CIS 12.5",
        "title": "Centralize Network Authentication, Authorization, and Auditing (AAA)",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Centralize network AAA.",
        "keywords": ["RADIUS", "AAA", "TACACS", "network authentication", "IG2"],
        "guidance": "Deploy RADIUS or TACACS+ to centralize authentication for network device access; correlate network AAA logs in the SIEM."
    },
    {
        "control_id": "CIS 12.6",
        "title": "Use of Secure Network Management and Communication Protocols",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Use secure network management and communication protocols (e.g., 802.1X, Wi-Fi Protected Access 2 (WPA2) Enterprise or greater).",
        "keywords": ["802.1X", "WPA2", "SNMP v3", "secure protocols", "IG2"],
        "guidance": "Enforce 802.1X for wired and WPA2/3 Enterprise for wireless; use SNMPv3 and disable SNMPv1/v2; disable Telnet/FTP on network devices."
    },
    {
        "control_id": "CIS 12.7",
        "title": "Ensure Remote Devices Utilize a VPN and Connect to Enterprise AAA Infrastructure",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Require that remote devices utilize a VPN and are connecting to the enterprise's AAA infrastructure prior to accessing enterprise resources.",
        "keywords": ["VPN", "remote access", "AAA", "IG2"],
        "guidance": "Enforce always-on VPN for remote workers; route traffic through enterprise security controls and AAA."
    },
    {
        "control_id": "CIS 12.8",
        "title": "Establish and Maintain Dedicated Computing Resources for All Administrative Work",
        "category": "CIS Control 12 – Network Infrastructure Management",
        "description": "Establish and maintain dedicated computing resources, either physically or logically separated, for all administrative tasks or tasks requiring administrative access. The resources should be segmented from the primary enterprise network and should not be able to access the internet.",
        "keywords": ["privileged access workstation", "PAW", "jump server", "admin isolation", "IG3"],
        "guidance": "Provide dedicated PAWs or secure admin jump hosts with no internet access for all privileged administration tasks."
    },
    # ── CIS Control 13: Network Monitoring and Defense ────────────────────────
    {
        "control_id": "CIS 13.1",
        "title": "Centralize Security Event Alerting",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Centralize security event alerting across enterprise assets for log correlation and analysis. Best practice implementation requires the use of a SIEM, which includes vendor-defined event correlation alerts.",
        "keywords": ["SIEM", "event correlation", "centralized alerting", "IG2"],
        "guidance": "Deploy a SIEM; define correlation rules for critical attack patterns; tune alert thresholds to reduce false positives."
    },
    {
        "control_id": "CIS 13.2",
        "title": "Deploy a Host-Based Intrusion Detection Solution",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Deploy a host-based intrusion detection solution on enterprise assets, where appropriate and/or supported. Example implementations include using endpoint detection and response (EDR) client software.",
        "keywords": ["HIDS", "endpoint detection", "EDR", "host intrusion", "IG2"],
        "guidance": "Deploy EDR agents on all enterprise endpoints and servers; configure them to stream telemetry to the SIEM."
    },
    {
        "control_id": "CIS 13.3",
        "title": "Deploy a Network Intrusion Detection Solution",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Deploy a network intrusion detection solution on enterprise assets, where appropriate. Example implementations include the use of a Network Intrusion Detection System (NIDS) or equivalent CSP service.",
        "keywords": ["NIDS", "network intrusion detection", "IDS", "IG2"],
        "guidance": "Position NIDS sensors at key network chokepoints; integrate with SIEM for centralized visibility and alert escalation."
    },
    {
        "control_id": "CIS 13.4",
        "title": "Perform Traffic Filtering Between Network Segments",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Perform traffic filtering between network segments, where appropriate.",
        "keywords": ["network segmentation", "inter-VLAN filtering", "firewall rules", "IG2"],
        "guidance": "Apply firewall policies between each security zone; use default-deny between sensitive segments and log all inter-zone traffic."
    },
    {
        "control_id": "CIS 13.5",
        "title": "Manage Access Control for Remote Assets",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Manage access control for assets remotely connecting to enterprise resources. Determine amount of access based on: up-to-date anti-malware software, configuration compliance, and ensuring the OS and applications are up-to-date.",
        "keywords": ["remote access", "network access control", "NAC", "device compliance", "IG2"],
        "guidance": "Deploy NAC to verify device health posture before granting remote access; quarantine non-compliant devices."
    },
    {
        "control_id": "CIS 13.6",
        "title": "Collect Network Traffic Flow Logs",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Collect network traffic flow logs and/or network traffic to review and alert upon, from network devices.",
        "keywords": ["NetFlow", "network flow logs", "traffic analysis", "IG2"],
        "guidance": "Enable NetFlow/IPFIX on routers and switches; forward flow data to the SIEM for baseline analysis and anomaly detection."
    },
    {
        "control_id": "CIS 13.7",
        "title": "Deploy a Host-Based Intrusion Prevention Solution",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Deploy a host-based intrusion prevention solution on enterprise assets, where appropriate and/or supported. Example implementations include use of an Endpoint Detection and Response (EDR) client.",
        "keywords": ["HIPS", "endpoint prevention", "EDR", "host protection", "IG3"],
        "guidance": "Enable automated blocking rules in the EDR (not just detection mode) for endpoints handling sensitive data."
    },
    {
        "control_id": "CIS 13.8",
        "title": "Deploy a Network Intrusion Prevention Solution",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Deploy a network intrusion prevention solution, where appropriate. Example implementations include the use of a Network Intrusion Prevention System (NIPS) or equivalent CSP service.",
        "keywords": ["NIPS", "network intrusion prevention", "IPS", "inline IPS", "IG3"],
        "guidance": "Deploy IPS in inline mode at critical network chokepoints; keep signature sets and custom rules current."
    },
    {
        "control_id": "CIS 13.9",
        "title": "Deploy Port-Level Access Control",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Deploy port-level access control. Port-level access control utilizes 802.1X, or similar network access control protocols, such that only authorized devices can connect to the network.",
        "keywords": ["802.1X", "port access control", "NAC", "network admission", "IG3"],
        "guidance": "Configure 802.1X on all switch ports; use certificates or MAB (MAC Authentication Bypass) as fallback."
    },
    {
        "control_id": "CIS 13.10",
        "title": "Perform Application Layer Filtering",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Perform application layer filtering. Example implementations include a filtering proxy or a next-generation firewall (NGFW) that filters or blocks based on specific application layer protocols.",
        "keywords": ["application layer filtering", "NGFW", "deep packet inspection", "proxy filtering", "IG3"],
        "guidance": "Deploy an NGFW or proxy to inspect and filter application-layer protocols; create rules aligned with approved application inventory."
    },
    {
        "control_id": "CIS 13.11",
        "title": "Tune Security Event Alerting Thresholds",
        "category": "CIS Control 13 – Network Monitoring and Defense",
        "description": "Tune security event alerting thresholds monthly, or more frequently.",
        "keywords": ["alert tuning", "SIEM tuning", "false positives", "IG3"],
        "guidance": "Review SIEM alert performance monthly; retire noisy rules, tune thresholds, and introduce new detections based on threat intelligence."
    },
    # ── CIS Control 14: Security Awareness and Skills Training ─────────────────
    {
        "control_id": "CIS 14.1",
        "title": "Establish and Maintain a Security Awareness Program",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Establish and maintain a security awareness program. Conduct training at hire and, at a minimum, annually. Review and update content annually.",
        "keywords": ["security awareness", "training program", "annual training", "IG1"],
        "guidance": "Deploy an LMS-based awareness program with role-tailored modules; track completion and enforce re-training for failures."
    },
    {
        "control_id": "CIS 14.2",
        "title": "Train Workforce Members to Recognize Social Engineering Attacks",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Train workforce members to recognize social engineering attacks, such as phishing, pre-texting, and tailgating.",
        "keywords": ["phishing training", "social engineering", "awareness", "IG1"],
        "guidance": "Conduct simulated phishing campaigns quarterly; provide immediate training to users who click; track click-rate trends."
    },
    {
        "control_id": "CIS 14.3",
        "title": "Train Workforce Members on Authentication Best Practices",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Train workforce members on authentication best practices. Example topics include MFA, password composition, and credential management.",
        "keywords": ["authentication training", "password security", "MFA training", "IG1"],
        "guidance": "Include authentication best practices in onboarding and annual training; reinforce with password manager and MFA enrollment campaigns."
    },
    {
        "control_id": "CIS 14.4",
        "title": "Train Workforce on Data Handling Best Practices",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Train workforce members on data handling best practices, identifying sensitive data, and properly storing, transferring, archiving, and destroying data.",
        "keywords": ["data handling", "data classification training", "DLP training", "IG1"],
        "guidance": "Include data handling in annual training; use data classification scenarios that reflect the organization's actual data types."
    },
    {
        "control_id": "CIS 14.5",
        "title": "Train Workforce Members on Causes of Unintentional Data Exposure",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Train workforce members to be aware of causes for unintentional data exposure. Example topics include mis-delivery of sensitive data, losing a portable end-user device, or publishing data to unintended audiences.",
        "keywords": ["unintentional exposure", "data leak", "accidental disclosure", "IG1"],
        "guidance": "Use real-world case studies in training; simulate scenarios like misaddressed emails and unsecured USB drives."
    },
    {
        "control_id": "CIS 14.6",
        "title": "Train Workforce Members on Recognizing and Reporting Security Incidents",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Train workforce members on how to identify a potential incident and be able to report such an incident.",
        "keywords": ["incident reporting", "security incident", "awareness", "IG1"],
        "guidance": "Publicize the security incident reporting process; conduct tabletop exercises and reinforce reporting culture."
    },
    {
        "control_id": "CIS 14.7",
        "title": "Train Workforce on How to Identify and Report Missing Security Updates",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Train workforce on how to identify if their enterprise assets are missing security updates and how to report this.",
        "keywords": ["patch awareness", "update notification", "missing updates", "IG2"],
        "guidance": "Show workforce how to identify overdue updates on their devices; communicate the self-service remediation or escalation path."
    },
    {
        "control_id": "CIS 14.8",
        "title": "Train Workforce on Dangers of Connecting to Insecure Networks",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Train workforce members on the dangers of connecting to and transmitting data over insecure networks for enterprise activities. If possible, configure enterprise IT to prevent connection to insecure networks.",
        "keywords": ["insecure networks", "public Wi-Fi", "network security", "IG2"],
        "guidance": "Educate employees on VPN usage over public networks; enforce always-on VPN through MDM to eliminate insecure connections."
    },
    {
        "control_id": "CIS 14.9",
        "title": "Conduct Role-Specific Security Awareness and Skills Training",
        "category": "CIS Control 14 – Security Awareness and Skills Training",
        "description": "Conduct role-specific security awareness and skills training. Example implementations include secure software development for developers, incident response training for incident responders, and advanced social engineering training for high-profile positions.",
        "keywords": ["role-based training", "developer security training", "incident response training", "IG2"],
        "guidance": "Map training curriculum to job function; require specific certifications or training hours for high-risk roles."
    },
    # ── CIS Control 15: Service Provider Management ───────────────────────────
    {
        "control_id": "CIS 15.1",
        "title": "Establish and Maintain an Inventory of Service Providers",
        "category": "CIS Control 15 – Service Provider Management",
        "description": "Establish and maintain an inventory of service providers. The inventory is to list all known service providers, include classification and contact information. Review and update the inventory annually.",
        "keywords": ["vendor inventory", "service provider", "third party", "IG1"],
        "guidance": "Maintain a register of all service providers with classification by data access level; review and update annually."
    },
    {
        "control_id": "CIS 15.2",
        "title": "Establish and Maintain a Service Provider Management Policy",
        "category": "CIS Control 15 – Service Provider Management",
        "description": "Establish and maintain a service provider management policy. Ensure the policy addresses the classification, inventory, assessment, monitoring, and decommissioning of service providers. Review and update the policy annually.",
        "keywords": ["vendor policy", "third-party policy", "supplier management", "IG2"],
        "guidance": "Define security requirements for vendor relationships; include data protection, incident notification, and audit rights."
    },
    {
        "control_id": "CIS 15.3",
        "title": "Classify Service Providers",
        "category": "CIS Control 15 – Service Provider Management",
        "description": "Classify service providers. Classification considerations may include data sensitivity, data volume, availability requirements, applicable regulations, inherent risk, and mitigated risk. Update and review classifications annually.",
        "keywords": ["vendor classification", "third-party risk", "risk tiering", "IG2"],
        "guidance": "Use a risk-based tiering model; assign higher scrutiny and more frequent assessments to top-tier vendors."
    },
    {
        "control_id": "CIS 15.4",
        "title": "Ensure Service Provider Contracts Include Security Requirements",
        "category": "CIS Control 15 – Service Provider Management",
        "description": "Ensure service provider contracts include security requirements. Example requirements may include minimum security program requirements, security incident and breach notification, data encryption requirements, and data disposal requirements.",
        "keywords": ["vendor contracts", "DPA", "security SLA", "supplier requirements", "IG2"],
        "guidance": "Include security annexes in all vendor contracts; require compliance with specified controls and breach notification timelines."
    },
    {
        "control_id": "CIS 15.5",
        "title": "Assess Service Providers",
        "category": "CIS Control 15 – Service Provider Management",
        "description": "Assess service providers consistent with the enterprise's service provider management policy. Assessment scope may vary based on classification.",
        "keywords": ["vendor assessment", "third-party audit", "vendor risk assessment", "IG2"],
        "guidance": "Use security questionnaires (CAIQ, SIG), SOC2 reports, and penetration test summaries to assess vendors by risk tier."
    },
    {
        "control_id": "CIS 15.6",
        "title": "Monitor Service Providers",
        "category": "CIS Control 15 – Service Provider Management",
        "description": "Monitor service providers consistent with the enterprise's service provider management policy. Monitoring may include periodic reassessment of service provider classification, monitoring service provider news for data breach notifications, and tracking service provider audit reports.",
        "keywords": ["vendor monitoring", "continuous monitoring", "third-party news", "IG2"],
        "guidance": "Subscribe to vendor security bulletins; use external risk intelligence feeds to monitor vendor breach disclosures."
    },
    {
        "control_id": "CIS 15.7",
        "title": "Securely Decommission Service Providers",
        "category": "CIS Control 15 – Service Provider Management",
        "description": "Securely decommission service providers. Example considerations include user and service account deactivation, termination of data flows, and secure disposal of enterprise data.",
        "keywords": ["vendor offboarding", "decommission", "access termination", "IG3"],
        "guidance": "Follow a formal off-boarding checklist: revoke access, delete data per contract, obtain decommission confirmation."
    },
    # ── CIS Control 16: Application Software Security ─────────────────────────
    {
        "control_id": "CIS 16.1",
        "title": "Establish and Maintain a Secure Application Development Process",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Establish and maintain a secure application development process. In the process, address secure application design standards, secure coding practices, developer training, vulnerability management, security of third-party code, and required security attributes. Review and update the process annually.",
        "keywords": ["SDLC", "secure development", "DevSecOps", "IG2"],
        "guidance": "Adopt a formal SSDLC policy that includes threat modeling, code review, and security testing gates before release."
    },
    {
        "control_id": "CIS 16.2",
        "title": "Establish and Maintain a Process to Accept and Address Software Vulnerabilities",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Establish and maintain a process to accept and address reports of software vulnerabilities, including providing a means for external entities to report. The process is to include a vulnerability response policy, a timeline to respond, and a timeline to develop and deliver security patches.",
        "keywords": ["vulnerability disclosure", "CVD", "responsible disclosure", "bug bounty", "IG2"],
        "guidance": "Publish a security.txt with a vulnerability reporting contact; define internal SLAs for triaging and patching reported vulnerabilities."
    },
    {
        "control_id": "CIS 16.3",
        "title": "Perform Root Cause Analysis on Security Vulnerabilities",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Perform root cause analysis on security vulnerabilities. When reviewing vulnerabilities, root cause analysis is the task of defining the problem, isolating the source of the vulnerability, and developing a corrective action. The root cause analysis results should feed back into the secure application development process.",
        "keywords": ["root cause analysis", "RCA", "vulnerability root cause", "IG2"],
        "guidance": "Document RCA for all CVSS High/Critical findings; feed root causes back into developer training and secure coding standards."
    },
    {
        "control_id": "CIS 16.4",
        "title": "Establish and Maintain Security Testing in the Development Lifecycle",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Establish and maintain security testing processes for in-house developed software and configured technology, including both pre-deployment and ongoing testing processes.",
        "keywords": ["SAST", "DAST", "security testing", "code review", "IG2"],
        "guidance": "Integrate SAST tools in the CI/CD pipeline; perform DAST against staging environments; gate releases on security test pass."
    },
    {
        "control_id": "CIS 16.5",
        "title": "Use Up-to-Date and Trusted Third-Party Software Components",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Use up-to-date and trusted third-party software components. When possible, choose established and proven frameworks and libraries. Utilize software composition analysis tools to identify third-party components with known vulnerabilities.",
        "keywords": ["SCA", "third-party components", "open source", "dependency management", "IG2"],
        "guidance": "Run SCA (Snyk, Dependabot, etc.) on every repository; enforce policies blocking deployment when critical CVEs exist in dependencies."
    },
    {
        "control_id": "CIS 16.6",
        "title": "Establish and Maintain a Severity Rating System for Application Vulnerabilities",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Establish and maintain a severity rating system and process for application vulnerabilities that allows the enterprise to prioritize which vulnerabilities to remediate first. This process includes setting a minimum level of security acceptability for releasing code or applications.",
        "keywords": ["vulnerability severity", "CVSS", "risk rating", "IG2"],
        "guidance": "Adopt a consistent scoring methodology (CVSS + business context) and publish remediation SLAs per severity tier."
    },
    {
        "control_id": "CIS 16.7",
        "title": "Use Standard Hardening Configuration Templates for Application Infrastructure",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Use standard, industry-recommended hardening configuration templates for application infrastructure components, including underlying servers, databases, web servers, cloud containers, PaaS components, and SaaS components.",
        "keywords": ["application hardening", "server hardening", "container hardening", "IG2"],
        "guidance": "Apply CIS Benchmarks for each application infrastructure component; automate drift detection via configuration compliance tools."
    },
    {
        "control_id": "CIS 16.8",
        "title": "Separate Production and Non-Production Systems",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Maintain separate environments for production and non-production systems.",
        "keywords": ["environment separation", "prod/dev isolation", "non-production", "IG2"],
        "guidance": "Enforce network and IAM segregation between production and non-production environments; prohibit production data in non-production systems."
    },
    {
        "control_id": "CIS 16.9",
        "title": "Train Developers in Application Security Concepts and Secure Coding",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Ensure that all software development personnel receive training in writing secure code for their specific development environment and responsibilities. Conduct training at least annually and update content as needed.",
        "keywords": ["developer training", "secure coding", "OWASP training", "IG2"],
        "guidance": "Require developers to complete OWASP-aligned secure coding training annually; track completion and assess competency."
    },
    {
        "control_id": "CIS 16.10",
        "title": "Apply Secure Design Principles in Application Architectures",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Apply secure design principles in application architectures. Example secure design principles include the concept of least privilege and attack surface minimization.",
        "keywords": ["secure design", "least privilege", "attack surface", "IG2"],
        "guidance": "Conduct architectural security reviews; apply defense-in-depth, least privilege, and fail-secure principles in all new designs."
    },
    {
        "control_id": "CIS 16.11",
        "title": "Leverage Vetted Modules or Services for Application Security Components",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Leverage vetted modules or services for application security components, such as identity management, encryption, and auditing and logging. Using platform features in critical security functions will reduce developers' workload and minimize the likelihood of design or implementation errors.",
        "keywords": ["security components", "vetted libraries", "crypto library", "identity SDK", "IG2"],
        "guidance": "Standardize on approved cryptographic libraries and identity SDKs; prohibit custom implementations of cryptography or session management."
    },
    {
        "control_id": "CIS 16.12",
        "title": "Implement Code-Level Security Checks",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Apply static and dynamic analysis tools to verify that secure coding practices are being adhered to for internally developed software.",
        "keywords": ["static analysis", "SAST", "dynamic analysis", "DAST", "code review", "IG2"],
        "guidance": "Integrate SAST in code review; run DAST against staging after each deployment; treat high-severity findings as build-blockers."
    },
    {
        "control_id": "CIS 16.13",
        "title": "Conduct Application Penetration Testing",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Conduct application penetration testing. For critical applications, authenticated and unauthenticated tests are performed annually, at a minimum, and ideally more frequently.",
        "keywords": ["application pentest", "penetration testing", "web application pentest", "IG3"],
        "guidance": "Engage qualified testers to perform annual application penetration tests; scope to include authentication, authorization, and injection vectors."
    },
    {
        "control_id": "CIS 16.14",
        "title": "Conduct Threat Modeling",
        "category": "CIS Control 16 – Application Software Security",
        "description": "Conduct threat modeling. Threat modeling is the process of identifying and addressing application security design flaws before code is created. It is conducted through specially trained individuals who evaluate the application design and gauge security risks for each entry point and component.",
        "keywords": ["threat modeling", "STRIDE", "design review", "attack surface", "IG3"],
        "guidance": "Require threat modeling (STRIDE or similar) for all new applications and significant feature changes; document mitigations per threat."
    },
    # ── CIS Control 17: Incident Response Management ──────────────────────────
    {
        "control_id": "CIS 17.1",
        "title": "Designate Personnel to Manage Incident Handling",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Designate one key person, and at least one backup, who will manage the enterprise's incident handling process. Management personnel are responsible for the coordination and documentation of incident response and recovery efforts.",
        "keywords": ["incident manager", "CIRT", "incident coordinator", "IG1"],
        "guidance": "Assign a named incident response owner and backup; ensure 24/7 reachability and escalation procedures are documented."
    },
    {
        "control_id": "CIS 17.2",
        "title": "Establish and Maintain Contact Information for Reporting Security Incidents",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Establish and maintain contact information for parties that need to be informed of security incidents. Contacts to consider include internal teams (legal, HR), insurance carriers, relevant government agencies, ISACs, external forensic experts, and incident response consultants.",
        "keywords": ["incident contacts", "breach notification", "ISAC", "legal", "IG1"],
        "guidance": "Maintain an up-to-date contact sheet covering legal, HR, PR, regulators, law enforcement, and external IR retainers."
    },
    {
        "control_id": "CIS 17.3",
        "title": "Establish and Maintain an Enterprise Process for Reporting Incidents",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Establish and maintain an enterprise process for the workforce to report security incidents. The process includes reporting timeframe, personnel to report to, mechanism for reporting, and the minimum information to be reported.",
        "keywords": ["incident reporting", "report process", "workforce reporting", "IG1"],
        "guidance": "Publicize a clear, low-barrier incident reporting mechanism; provide examples of what constitutes a reportable security event."
    },
    {
        "control_id": "CIS 17.4",
        "title": "Establish and Maintain an Incident Response Process",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Establish and maintain an incident response process that addresses roles and responsibilities, compliance requirements, and a communication plan. Review annually.",
        "keywords": ["incident response process", "IR plan", "IR playbook", "IG2"],
        "guidance": "Write a formal IR plan covering preparation, identification, containment, eradication, recovery, and lessons learned; test it annually."
    },
    {
        "control_id": "CIS 17.5",
        "title": "Assign Key Roles and Responsibilities for Incident Response",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Assign key roles and responsibilities for incident response, including staff from legal, IT, information security, facilities, public relations, human resources, incident responders, and analysts, as applicable.",
        "keywords": ["IR roles", "RACI", "incident response team", "IG2"],
        "guidance": "Document a RACI for incident response roles; ensure all named stakeholders are briefed and have access to the IR plan."
    },
    {
        "control_id": "CIS 17.6",
        "title": "Define Mechanisms for Communicating During Incident Response",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Determine which primary and secondary mechanisms will be used to communicate and report during a security incident. Keep in mind that certain mechanisms may be compromised during an incident.",
        "keywords": ["IR communication", "out-of-band communication", "incident notification", "IG2"],
        "guidance": "Pre-establish out-of-band communication channels (phone trees, Signal groups) in case email and enterprise tools are compromised."
    },
    {
        "control_id": "CIS 17.7",
        "title": "Conduct Routine Incident Response Exercises",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Plan and conduct routine incident response exercises and scenarios for the workforce involved in the incident response to maintain awareness and comfort in responding to real-world threats.",
        "keywords": ["tabletop exercise", "IR drill", "incident exercise", "IG2"],
        "guidance": "Conduct at least one tabletop exercise and one live-fire drill annually; document gaps and update the IR plan accordingly."
    },
    {
        "control_id": "CIS 17.8",
        "title": "Conduct Post-Incident Reviews",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Conduct post-incident reviews. Post-incident reviews help prevent incident recurrence through identifying lessons learned and follow-up action.",
        "keywords": ["post-incident review", "lessons learned", "after action report", "IG2"],
        "guidance": "Hold a post-mortem within 2 weeks of incident closure; produce a written report with actionable findings and assign owners."
    },
    {
        "control_id": "CIS 17.9",
        "title": "Establish and Maintain Security Incident Thresholds",
        "category": "CIS Control 17 – Incident Response Management",
        "description": "Establish and maintain security incident thresholds, including, at a minimum, differentiating between an incident and an event, and the definition of a major incident. Review annually.",
        "keywords": ["incident threshold", "major incident", "incident definition", "event vs incident", "IG2"],
        "guidance": "Define severity levels (SEV1-SEV4) with clear escalation triggers; align definitions with regulatory reporting obligations."
    },
    # ── CIS Control 18: Penetration Testing ───────────────────────────────────
    {
        "control_id": "CIS 18.1",
        "title": "Establish and Maintain a Penetration Testing Program",
        "category": "CIS Control 18 – Penetration Testing",
        "description": "Establish and maintain a penetration testing program appropriate to the size, complexity, and maturity of the enterprise. A penetration testing program includes a policy with at least annual individual tests for network and application layers.",
        "keywords": ["penetration testing", "pentest program", "red team", "IG2"],
        "guidance": "Define scope, frequency, and methodology for penetration tests; maintain a register of past tests and open findings."
    },
    {
        "control_id": "CIS 18.2",
        "title": "Perform Periodic External Penetration Tests",
        "category": "CIS Control 18 – Penetration Testing",
        "description": "Perform periodic external penetration tests based on program requirements, no less than annually. External penetration testing must include enterprise and environmental reconnaissance to identify targets.",
        "keywords": ["external pentest", "external attack surface", "periodic testing", "IG2"],
        "guidance": "Commission external penetration tests at least annually; rotate testing firms every few years to get fresh perspective."
    },
    {
        "control_id": "CIS 18.3",
        "title": "Remediate Penetration Test Findings",
        "category": "CIS Control 18 – Penetration Testing",
        "description": "Remediate penetration test findings based on the enterprise's policy for remediation scope and prioritization.",
        "keywords": ["pentest remediation", "finding remediation", "risk remediation", "IG2"],
        "guidance": "Track all pentest findings in the vulnerability management platform; require remediation within defined SLAs by severity."
    },
    {
        "control_id": "CIS 18.4",
        "title": "Validate Security Measures",
        "category": "CIS Control 18 – Penetration Testing",
        "description": "Validate security measures after each penetration test. If deemed necessary, modify rulesets and capabilities to detect the techniques used during testing.",
        "keywords": ["control validation", "security testing", "defense validation", "IG3"],
        "guidance": "After each pentest, validate that detection and prevention controls triggered appropriately; update SIEM rules for missed techniques."
    },
    {
        "control_id": "CIS 18.5",
        "title": "Perform Periodic Internal Penetration Tests",
        "category": "CIS Control 18 – Penetration Testing",
        "description": "Perform periodic internal penetration tests based on program requirements, no less than annually. The testing may be clear box or opaque box.",
        "keywords": ["internal pentest", "insider threat", "lateral movement testing", "IG3"],
        "guidance": "Conduct annual internal penetration tests simulating insider threat and lateral movement scenarios; include Active Directory attacks in scope."
    },
]


def main():
    payload = {"framework": FRAMEWORK, "controls": CONTROLS}
    output = json.dumps(payload, indent=2, ensure_ascii=False)
    CORPUS_FILE.write_text(output, encoding="utf-8")
    print(f"Wrote {len(CONTROLS)} CIS safeguards to {CORPUS_FILE}")


if __name__ == "__main__":
    main()
