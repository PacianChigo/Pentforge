"""Assign severity, reason, and remediation to findings based on port/service."""

from pentforge.models import Finding, ScanReport

# Port-based severity rules
# Format: port -> (severity, reason, remediation)
PORT_RULES: dict[int, tuple[str, str, str]] = {
    21: (
        "high",
        "FTP transmits credentials and data in cleartext.",
        "Disable FTP. Replace with SFTP or FTPS. If FTP is required, restrict to trusted IPs.",
    ),
    23: (
        "critical",
        "Telnet transmits everything (including credentials) in cleartext.",
        "Disable Telnet immediately. Use SSH instead.",
    ),
    25: (
        "low",
        "SMTP exposed. May allow user enumeration or open relay if misconfigured.",
        "Restrict SMTP to internal mail relays. Disable open relay.",
    ),
    53: (
        "low",
        "DNS service exposed. May allow zone transfers or cache poisoning.",
        "Restrict DNS to trusted networks. Disable recursion for external queries.",
    ),
    135: (
        "medium",
        "MSRPC exposed. Often used for lateral movement in Windows environments.",
        "Block MSRPC at the perimeter. Restrict to internal network.",
    ),
    139: (
        "high",
        "NetBIOS exposed. Can leak system info and enable lateral movement.",
        "Block NetBIOS at the perimeter. Disable if not required.",
    ),
    445: (
        "critical",
        "SMB exposed. Historically vulnerable (EternalBlue/MS17-010) and used for lateral movement.",
        "Block SMB at the perimeter. Patch immediately. Restrict to internal networks.",
    ),
    1433: (
        "high",
        "MSSQL database port exposed to the network.",
        "Firewall port 1433. Allow only from application servers.",
    ),
    1521: (
        "high",
        "Oracle database port exposed to the network.",
        "Firewall port 1521. Allow only from application servers.",
    ),
    3306: (
        "high",
        "MySQL database port exposed to the network.",
        "Firewall port 3306. Allow only from application servers.",
    ),
    3389: (
        "critical",
        "RDP exposed. Frequent target of brute-force and ransomware attacks.",
        "Do not expose RDP to the internet. Use VPN or a bastion host with MFA.",
    ),
    5432: (
        "high",
        "PostgreSQL database port exposed to the network.",
        "Firewall port 5432. Allow only from application servers.",
    ),
    5900: (
        "high",
        "VNC exposed. Often weakly authenticated or unauthenticated.",
        "Restrict VNC to internal networks. Require strong authentication.",
    ),
    6379: (
        "critical",
        "Redis exposed. Usually unauthenticated by default — allows remote code execution.",
        "Bind Redis to localhost. Never expose to the internet. Enable auth.",
    ),
    9200: (
        "critical",
        "Elasticsearch exposed. Usually unauthenticated — leaks all indexed data.",
        "Restrict Elasticsearch to internal networks. Enable authentication.",
    ),
    11211: (
        "high",
        "Memcached exposed. Can be abused for amplification DDoS attacks.",
        "Bind Memcached to localhost. Block UDP/11211 at the perimeter.",
    ),
    27017: (
        "critical",
        "MongoDB exposed. Historically unauthenticated by default — leaks all data.",
        "Bind MongoDB to localhost or internal network. Enable authentication.",
    ),
}

# Service-name based rules (fallback when port isn't listed above)
SERVICE_RULES: dict[str, tuple[str, str, str]] = {
    "http": (
        "low",
        "HTTP service without TLS. Traffic is unencrypted.",
        "Enable HTTPS with a valid certificate. Redirect HTTP to HTTPS.",
    ),
    "http-alt": (
        "low",
        "HTTP service on a non-standard port. May be an administrative panel.",
        "Enable HTTPS. Restrict access to trusted networks.",
    ),
    "ftp": (
        "high",
        "FTP service. Credentials and data sent in cleartext.",
        "Replace with SFTP or FTPS.",
    ),
    "telnet": (
        "critical",
        "Telnet service. All traffic including credentials is cleartext.",
        "Disable Telnet. Use SSH.",
    ),
    "smtp": (
        "low",
        "SMTP service. May allow user enumeration.",
        "Restrict SMTP. Disable open relay.",
    ),
    "mysql": (
        "high",
        "MySQL database exposed.",
        "Firewall the port. Allow only from application servers.",
    ),
    "ms-sql-s": (
        "high",
        "Microsoft SQL Server exposed.",
        "Firewall the port. Allow only from application servers.",
    ),
    "postgresql": (
        "high",
        "PostgreSQL database exposed.",
        "Firewall the port. Allow only from application servers.",
    ),
    "redis": (
        "critical",
        "Redis exposed. Often unauthenticated.",
        "Bind Redis to localhost. Enable authentication.",
    ),
    "mongodb": (
        "critical",
        "MongoDB exposed. Often unauthenticated.",
        "Bind MongoDB to internal network. Enable authentication.",
    ),
    "vnc": (
        "high",
        "VNC remote desktop service exposed.",
        "Restrict to internal networks. Require strong authentication.",
    ),
    "rdp": (
        "critical",
        "Remote Desktop exposed to the network.",
        "Do not expose RDP. Use VPN with MFA.",
    ),
}

DEFAULT_RULE = (
    "info",
    "Open port detected. No specific risk identified by the rule set.",
    "Confirm the service is required. Restrict access if not needed.",
)


def enrich(report: ScanReport) -> ScanReport:
    """Apply severity rules to all findings in the report."""
    for finding in report.findings:
        severity, reason, remediation = _lookup(finding)
        finding.severity = severity
        finding.reason = reason
        finding.remediation = remediation
    return report


def _lookup(finding: Finding) -> tuple[str, str, str]:
    # Port rule takes priority
    if finding.port in PORT_RULES:
        return PORT_RULES[finding.port]

    # Then service name
    service = finding.service.lower()
    if service in SERVICE_RULES:
        return SERVICE_RULES[service]

    # Then product name
    product = finding.product.lower()
    for key, rule in SERVICE_RULES.items():
        if key in product:
            return rule

    return DEFAULT_RULE
