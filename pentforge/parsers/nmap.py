"""Parse nmap XML (-oX) output into Finding objects."""

from pathlib import Path

from defusedxml import ElementTree as ET

from pentforge.models import Finding, ScanMeta, ScanReport


def parse(path: str | Path) -> ScanReport:
    """Parse an nmap XML file and return a ScanReport."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Scan file not found: {path}")

    tree = ET.parse(str(path))
    root = tree.getroot()

    report = ScanReport()
    report.meta = _parse_meta(root)

    findings: list[Finding] = []
    for host in root.findall("host"):
        host_addr = _host_address(host)
        for port in host.findall("./ports/port"):
            finding = _parse_port(host_addr, port)
            if finding:
                findings.append(finding)

    report.findings = findings
    return report


def _parse_meta(root) -> ScanMeta:
    meta = ScanMeta()
    meta.nmap_version = root.get("version", "")
    meta.args = root.get("args", "")
    meta.scan_date = root.get("startstr", "")

    for host in root.findall("host"):
        addr = _host_address(host)
        if addr:
            meta.target = addr
            break
    return meta


def _host_address(host) -> str:
    """Prefer IPv4, fall back to IPv6 or hostname."""
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr", "")
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv6":
            return addr.get("addr", "")
    hostname = host.find("./hostnames/hostname")
    if hostname is not None:
        return hostname.get("name", "")
    return "unknown"


def _parse_port(host_addr: str, port) -> Finding | None:
    state_el = port.find("state")
    if state_el is None:
        return None
    state = state_el.get("state", "")

    # Only include open ports (skip closed/filtered)
    if state != "open":
        return None

    service_el = port.find("service")
    service = product = version = ""
    if service_el is not None:
        service = service_el.get("name", "")
        product = service_el.get("product", "")
        version = service_el.get("version", "")

    return Finding(
        host=host_addr,
        port=int(port.get("portid", "0")),
        protocol=port.get("protocol", "tcp"),
        state=state,
        service=service,
        product=product,
        version=version,
    )
