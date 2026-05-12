#!/usr/bin/env python3
"""
VulnScanner CLI.

Examples:
    python main.py scanme.nmap.org
    python main.py 192.168.1.1 --ports 1-65535 --no-cve
    python main.py example.com --format pdf --output report.pdf
    python main.py 10.0.0.1 --api-key YOUR_NVD_KEY
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scanner.core import VulnScanner
from scanner.report_html import generate_html
from scanner.report_pdf import generate_pdf


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


def print_banner() -> None:
    banner = r"""
 __   ___   _ _    _   _   ___   ___   ___   _   _   _  _  _  _  ___ ___
 \ \ / / | | | |  | \ | | / __| / __| / __| | | | | | \| || \| || __| _ \
  \ V /| |_| | |__| .` | \__ \| (__  | (__  | |_| | | .` || .` || _||   /
   \_/  \___/|____|_|\_| |___/ \___| \___| \___/  |_|\_||_|\_||___|_|_\

  Vulnerability Scanner v1.0 - For authorized testing only
"""
    print(banner)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VulnScanner - Port scanner + CVE lookup + report generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "--ports",
        "-p",
        default="1-1024",
        help="Port range to scan (default: 1-1024)",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "pdf", "both"],
        default="both",
        help="Report format (default: both)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output file path (auto-generated if not specified)",
    )
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip CVE lookup (faster scan)",
    )
    parser.add_argument(
        "--api-key",
        "-k",
        default=os.getenv("NVD_API_KEY"),
        help="NVD API key for higher rate limits (or set NVD_API_KEY env var)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        default=60,
        type=int,
        help="Nmap scan timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)
    print_banner()

    logger = logging.getLogger(__name__)

    print(f"  [!] Target: {args.target}")
    print(f"  [!] Ports:  {args.ports}")
    print(f"  [!] CVE lookup: {'disabled' if args.no_cve else 'enabled'}")
    print()
    confirm = input("  Do you have authorization to scan this target? [y/N] ")
    if confirm.strip().lower() != "y":
        print("  Aborted. Only scan systems you are authorized to test.")
        sys.exit(0)
    print()

    logger.info("Initializing scanner...")

    try:
        scanner = VulnScanner(api_key=args.api_key)
        result = scanner.scan(
            target=args.target,
            ports=args.ports,
            timeout=args.timeout,
            cve_lookup=not args.no_cve,
        )
    except (ValueError, RuntimeError) as exc:
        logger.error(str(exc))
        sys.exit(1)

    print(f"\n{'-' * 55}")
    print(f"  SCAN COMPLETE - {result.target} ({result.ip})")
    print(f"{'-' * 55}")
    print(f"  Open ports : {result.total_open}")
    print(f"  CVEs found : {result.total_cves}")
    print(f"  Risk level : {result.risk_level}")
    print(f"{'-' * 55}\n")

    if result.services:
        print(f"  {'PORT':<10} {'SERVICE':<15} {'VERSION':<30} CVEs")
        print(f"  {'-' * 70}")
        for svc in result.services:
            version = f"{svc.product} {svc.version}".strip()
            cve_info = f"{len(svc.cves)} CVE(s)" if svc.cves else "-"
            port_label = f"{svc.port}/{svc.protocol}"
            print(f"  {port_label:<10} {svc.name:<15} {version:<30} {cve_info}")
    print()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = result.target.replace(".", "_").replace(":", "_")

    Path("reports").mkdir(exist_ok=True)

    if args.format in ("html", "both"):
        html_path = (
            args.output
            if args.output and args.format == "html"
            else f"reports/{safe_target}_{timestamp}.html"
        )
        generate_html(result, html_path)
        logger.info("HTML report saved: %s", html_path)
        print(f"  [OK] HTML report: {html_path}")

    if args.format in ("pdf", "both"):
        pdf_path = (
            args.output
            if args.output and args.format == "pdf"
            else f"reports/{safe_target}_{timestamp}.pdf"
        )
        generate_pdf(result, pdf_path)
        logger.info("PDF report saved: %s", pdf_path)
        print(f"  [OK] PDF  report: {pdf_path}")

    print()


if __name__ == "__main__":
    main()
