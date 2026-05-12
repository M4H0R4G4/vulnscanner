"""
VulnScanner - Core scanning engine
Identifies open ports, service versions, and known CVEs via NVD API.
"""

import socket
import concurrent.futures
import logging
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

import requests

try:
    import nmap
except ImportError as exc:  # pragma: no cover - exercised by real CLI usage.
    nmap = None
    NMAP_IMPORT_ERROR = exc
else:
    NMAP_IMPORT_ERROR = None

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    state: str
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cves: list = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    hostname: str
    ip: str
    scan_time: str
    services: list[ServiceInfo] = field(default_factory=list)
    total_open: int = 0
    total_cves: int = 0
    risk_level: str = "LOW"


class NVDClient:
    """Queries the NVD (National Vulnerability Database) API for CVEs."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulnScanner/1.0"})
        if api_key:
            self.session.headers.update({"apiKey": api_key})

    def search_cves(self, keyword: str, max_results: int = 5) -> list[dict]:
        """Search CVEs by product/version keyword."""
        if not keyword or len(keyword) < 3:
            return []
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results,
            }
            resp = self.session.get(NVD_API_BASE, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_cves(data.get("vulnerabilities", []))
        except requests.exceptions.RequestException as e:
            logger.warning(f"NVD API error for '{keyword}': {e}")
            return []

    def _parse_cves(self, vulnerabilities: list) -> list[dict]:
        results = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available.",
            )
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"
            # Try CVSSv3.1 first, then v3.0, then v2
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    if key.startswith("cvssMetricV3"):
                        cvss_score = m.get("cvssData", {}).get("baseScore")
                        severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    else:
                        cvss_score = m.get("cvssData", {}).get("baseScore")
                        severity = m.get("baseSeverity", "UNKNOWN")
                    break

            results.append({
                "id": cve_id,
                "description": description[:300] + "..." if len(description) > 300 else description,
                "cvss_score": cvss_score,
                "severity": severity,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return results


class VulnScanner:
    """Main vulnerability scanner — wraps nmap + NVD lookups."""

    def __init__(self, api_key: Optional[str] = None):
        if nmap is None:
            raise RuntimeError(
                "python-nmap is not installed. Run: pip install -r requirements.txt"
            ) from NMAP_IMPORT_ERROR
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as exc:
            raise RuntimeError(
                "Nmap executable was not found. Install Nmap and make sure it is in PATH."
            ) from exc
        self.nvd = NVDClient(api_key=api_key)

    def scan(
        self,
        target: str,
        ports: str = "1-1024",
        timeout: int = 60,
        cve_lookup: bool = True,
    ) -> ScanResult:
        """
        Scan a target host for open ports and optional CVE lookup.

        Args:
            target: IP address or hostname
            ports: Port range string (e.g. '1-1024', '22,80,443')
            timeout: Nmap timeout in seconds
            cve_lookup: Whether to query NVD for CVEs
        """
        logger.info(f"Starting scan on {target} | ports: {ports}")
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
            hostname = socket.getfqdn(target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve host: {target}")

        # Run nmap with service/version detection
        try:
            self.nm.scan(
                hosts=ip,
                ports=ports,
                arguments="-sV --version-intensity 5 -T4",
                timeout=timeout,
            )
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap error: {e}. Make sure nmap is installed.")

        services = []
        if ip in self.nm.all_hosts():
            host_data = self.nm[ip]
            for proto in host_data.all_protocols():
                for port in sorted(host_data[proto].keys()):
                    p = host_data[proto][port]
                    if p["state"] == "open":
                        svc = ServiceInfo(
                            port=port,
                            protocol=proto,
                            state=p["state"],
                            name=p.get("name", "unknown"),
                            product=p.get("product", ""),
                            version=p.get("version", ""),
                            extrainfo=p.get("extrainfo", ""),
                        )
                        services.append(svc)

        # CVE lookup in parallel
        if cve_lookup and services:
            logger.info(f"Looking up CVEs for {len(services)} services...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(self._lookup_cves, svc): svc for svc in services
                }
                for future in concurrent.futures.as_completed(futures):
                    svc = futures[future]
                    try:
                        svc.cves = future.result()
                    except Exception as e:
                        logger.warning(f"CVE lookup failed for port {svc.port}: {e}")

        total_cves = sum(len(s.cves) for s in services)
        risk_level = self._calculate_risk(services)

        return ScanResult(
            target=target,
            hostname=hostname,
            ip=ip,
            scan_time=scan_time,
            services=services,
            total_open=len(services),
            total_cves=total_cves,
            risk_level=risk_level,
        )

    def _lookup_cves(self, svc: ServiceInfo) -> list[dict]:
        """Build a search keyword and query NVD."""
        parts = [svc.product, svc.version]
        keyword = " ".join(p for p in parts if p).strip()
        if not keyword:
            keyword = svc.name
        return self.nvd.search_cves(keyword, max_results=5)

    def _calculate_risk(self, services: list[ServiceInfo]) -> str:
        """Assign overall risk based on CVE severity scores."""
        max_score = 0.0
        for svc in services:
            for cve in svc.cves:
                score = cve.get("cvss_score") or 0
                if score > max_score:
                    max_score = score
        if max_score >= 9.0:
            return "CRITICAL"
        elif max_score >= 7.0:
            return "HIGH"
        elif max_score >= 4.0:
            return "MEDIUM"
        return "LOW"
