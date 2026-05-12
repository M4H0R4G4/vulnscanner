# 🔍 VulnScanner

> **Vulnerability scanner** that identifies open ports, service versions, and known CVEs — with professional HTML and PDF reports.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![NVD](https://img.shields.io/badge/Data-NVD%20API-orange?style=flat-square)

---

## ✨ Features

- **Port scanning** via nmap with service/version detection (`-sV`)
- **CVE lookup** via the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) for each detected service
- **Parallel CVE queries** using ThreadPoolExecutor
- **HTML report** — self-contained, dark-themed, with severity badges
- **PDF report** — professional layout with ReportLab, dark background
- **Risk scoring** — automatic CRITICAL / HIGH / MEDIUM / LOW classification
- **CLI interface** with authorization confirmation prompt
- **Python package support** with `pyproject.toml`, `setup.py`, and `vulnscan` console command

---

## 🚀 Quick Start

### Requirements

- Python 3.10+
- [nmap](https://nmap.org/download.html) installed on your system

```bash
# Install nmap (Debian/Ubuntu)
sudo apt install nmap

# Install nmap (macOS)
brew install nmap
```

For Windows, download and install Nmap from:

https://nmap.org/download.html

After installing, open a new terminal and confirm:

```bash
nmap --version
```

### Install

```bash
git clone https://github.com/YOUR_USERNAME/Vulnerability-Scanner-Personalizado.git
cd Vulnerability-Scanner-Personalizado
pip install -r requirements.txt
```

Optional editable install:

```bash
pip install -e .
```

### Run

```bash
# Basic scan (ports 1-1024)
python main.py scanme.nmap.org

# Custom port range
python main.py 192.168.1.1 --ports 1-65535

# PDF only, no CVE lookup (faster)
python main.py 10.0.0.5 --format pdf --no-cve

# HTML report with NVD API key (higher rate limits)
python main.py target.com --api-key YOUR_KEY --format html

# If installed with pip install -e .
vulnscan scanme.nmap.org --no-cve
```

---

## 📋 CLI Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--ports` | `-p` | `1-1024` | Port range to scan |
| `--format` | `-f` | `both` | `html`, `pdf`, or `both` |
| `--output` | `-o` | auto | Custom output file path |
| `--no-cve` | — | false | Skip NVD lookup (faster) |
| `--api-key` | `-k` | env | NVD API key |
| `--timeout` | `-t` | `60` | Nmap timeout (seconds) |
| `--verbose` | `-v` | false | Debug logging |

**Tip:** Set `NVD_API_KEY` as an environment variable to avoid passing it every time:

```bash
export NVD_API_KEY="your-key-here"
```

On Windows PowerShell:

```powershell
$env:NVD_API_KEY="your-key-here"
```

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

---

## 🧪 Running Tests

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

Run the test suite:

```bash
pytest
```

Expected result:

```text
17 passed
```

---

## 🗂️ Project Structure

```text
Vulnerability-Scanner-Personalizado/
├── main.py                    # CLI entrypoint
├── setup.py                   # Package installation config
├── pyproject.toml             # Modern build config
├── requirements.txt           # Runtime dependencies
├── requirements-dev.txt       # Test/development dependencies
├── README.md                  # Documentation
├── LICENSE                    # MIT license
├── .gitignore                 # Ignores cache, reports, env files
├── scanner/
│   ├── __init__.py
│   ├── core.py                # VulnScanner engine + NVD client
│   ├── report_html.py         # HTML report generator
│   └── report_pdf.py          # PDF report generator
├── reports/                   # Generated reports (gitignored)
└── tests/
    ├── __init__.py
    └── test_core.py           # Unit tests
```

---

## 📊 Sample Report

After scanning, reports are saved to the `reports/` folder:

```text
reports/
├── scanme_nmap_org_20260511_143201.html
└── scanme_nmap_org_20260511_143201.pdf
```

---

## ⚠️ Legal Disclaimer

**VulnScanner is for authorized security testing only.**

Only use this tool on systems you own or have explicit written permission to test. Unauthorized scanning may be illegal. The tool includes an authorization confirmation prompt before every scan.

---

## 🔧 Extending

### Add a new report format

Create `scanner/report_json.py` and implement:

```python
def generate_json(result: ScanResult, output_path: str) -> str:
    ...
```

### Use as a library

```python
from scanner.core import VulnScanner
from scanner.report_html import generate_html

scanner = VulnScanner(api_key="optional")
result = scanner.scan("192.168.1.1", ports="22,80,443")
generate_html(result, "report.html")
```

---

## 📚 References

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [MITRE CVE](https://cve.mitre.org/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [python-nmap](https://xael.org/pages/python-nmap-en.html)

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
