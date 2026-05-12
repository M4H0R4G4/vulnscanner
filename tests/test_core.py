"""
Unit tests for VulnScanner core components.
Run with: pytest tests/
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import pytest

# Mock nmap before any import so tests run without nmap installed
mock_nmap = MagicMock()
mock_scanner_instance = MagicMock()
mock_nmap.PortScanner.return_value = mock_scanner_instance
mock_nmap.PortScannerError = Exception
sys.modules.setdefault("nmap", mock_nmap)

from scanner.core import NVDClient, VulnScanner, ScanResult, ServiceInfo


class TestNVDClient:

    def setup_method(self):
        self.client = NVDClient()

    def test_search_cves_empty_keyword(self):
        result = self.client.search_cves("ab")
        assert result == []

    def test_parse_cves_structure(self):
        mock_vulns = [{
            "cve": {
                "id": "CVE-2023-1234",
                "descriptions": [{"lang": "en", "value": "Test vulnerability."}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                    }]
                }
            }
        }]
        result = self.client._parse_cves(mock_vulns)
        assert len(result) == 1
        cve = result[0]
        assert cve["id"] == "CVE-2023-1234"
        assert cve["cvss_score"] == 9.8
        assert cve["severity"] == "CRITICAL"
        assert "nvd.nist.gov" in cve["url"]

    def test_parse_cves_no_metrics(self):
        mock_vulns = [{
            "cve": {
                "id": "CVE-2023-9999",
                "descriptions": [{"lang": "en", "value": "No metrics."}],
                "metrics": {}
            }
        }]
        result = self.client._parse_cves(mock_vulns)
        assert result[0]["cvss_score"] is None
        assert result[0]["severity"] == "UNKNOWN"

    @patch("scanner.core.requests.Session.get")
    def test_search_cves_api_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("timeout")
        result = self.client.search_cves("openssl")
        assert result == []

    def test_parse_cves_long_description_truncated(self):
        long_desc = "A" * 400
        mock_vulns = [{
            "cve": {
                "id": "CVE-2023-0001",
                "descriptions": [{"lang": "en", "value": long_desc}],
                "metrics": {}
            }
        }]
        result = self.client._parse_cves(mock_vulns)
        assert len(result[0]["description"]) <= 305


class TestVulnScannerRisk:

    def setup_method(self):
        self.scanner = VulnScanner()

    def _make_service(self, cves):
        svc = ServiceInfo(port=80, protocol="tcp", state="open", name="http")
        svc.cves = cves
        return svc

    def test_risk_critical(self):
        services = [self._make_service([{"cvss_score": 9.8, "severity": "CRITICAL"}])]
        assert self.scanner._calculate_risk(services) == "CRITICAL"

    def test_risk_high(self):
        services = [self._make_service([{"cvss_score": 7.5, "severity": "HIGH"}])]
        assert self.scanner._calculate_risk(services) == "HIGH"

    def test_risk_medium(self):
        services = [self._make_service([{"cvss_score": 5.0, "severity": "MEDIUM"}])]
        assert self.scanner._calculate_risk(services) == "MEDIUM"

    def test_risk_low_no_cves(self):
        services = [self._make_service([])]
        assert self.scanner._calculate_risk(services) == "LOW"

    def test_risk_uses_highest_score(self):
        services = [
            self._make_service([{"cvss_score": 3.1, "severity": "LOW"}]),
            self._make_service([{"cvss_score": 9.1, "severity": "CRITICAL"}]),
        ]
        assert self.scanner._calculate_risk(services) == "CRITICAL"

    def test_risk_none_score(self):
        services = [self._make_service([{"cvss_score": None, "severity": "UNKNOWN"}])]
        assert self.scanner._calculate_risk(services) == "LOW"

    def test_risk_boundary_9(self):
        services = [self._make_service([{"cvss_score": 9.0, "severity": "CRITICAL"}])]
        assert self.scanner._calculate_risk(services) == "CRITICAL"

    def test_risk_boundary_7(self):
        services = [self._make_service([{"cvss_score": 7.0, "severity": "HIGH"}])]
        assert self.scanner._calculate_risk(services) == "HIGH"


class TestReports:
    def _output_path(self, name: str) -> str:
        output_dir = Path("test_outputs")
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / name
        if output_path.exists():
            output_path.unlink()
        return str(output_path)

    def _make_result(self):
        svc = ServiceInfo(
            port=22, protocol="tcp", state="open",
            name="ssh", product="OpenSSH", version="8.2"
        )
        svc.cves = [{
            "id": "CVE-2023-38408",
            "description": "Remote code execution via PKCS#11.",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        }]
        return ScanResult(
            target="192.168.1.1", hostname="test.local", ip="192.168.1.1",
            scan_time="2026-05-11 12:00:00", services=[svc],
            total_open=1, total_cves=1, risk_level="CRITICAL",
        )

    def test_html_report_generates(self):
        from scanner.report_html import generate_html
        result = self._make_result()
        out = self._output_path("report.html")
        path = generate_html(result, out)
        content = Path(path).read_text()
        assert "192.168.1.1" in content
        assert "CVE-2023-38408" in content
        assert "CRITICAL" in content
        assert "OpenSSH" in content

    def test_html_report_no_services(self):
        from scanner.report_html import generate_html
        result = ScanResult(
            target="10.0.0.1", hostname="empty.local", ip="10.0.0.1",
            scan_time="2026-05-11 12:00:00", services=[],
            total_open=0, total_cves=0, risk_level="LOW",
        )
        out = self._output_path("empty.html")
        path = generate_html(result, out)
        content = Path(path).read_text()
        assert "10.0.0.1" in content
        assert "No open ports" in content

    def test_pdf_report_generates(self):
        from scanner.report_pdf import generate_pdf
        result = self._make_result()
        out = self._output_path("report.pdf")
        path = generate_pdf(result, out)
        assert Path(path).read_bytes()[:4] == b"%PDF"

    def test_pdf_report_no_cves(self):
        from scanner.report_pdf import generate_pdf
        svc = ServiceInfo(port=80, protocol="tcp", state="open", name="http")
        svc.cves = []
        result = ScanResult(
            target="10.0.0.1", hostname="clean.local", ip="10.0.0.1",
            scan_time="2026-05-11 12:00:00", services=[svc],
            total_open=1, total_cves=0, risk_level="LOW",
        )
        out = self._output_path("clean.pdf")
        path = generate_pdf(result, out)
        assert Path(path).read_bytes()[:4] == b"%PDF"
