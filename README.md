# VulnScanner Personalizado

VulnScanner Personalizado is a command-line vulnerability scanner for authorized security testing. It uses Nmap for port and service/version detection, queries the NVD API for related CVEs, and generates HTML and PDF reports.

## Features

- Port scanning with Nmap service/version detection.
- Optional CVE lookup through the NVD API 2.0.
- Parallel CVE queries for detected services.
- Risk classification: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- Self-contained HTML report.
- PDF report generated with ReportLab.
- CLI authorization confirmation before scanning.
- Unit tests for core logic and report generation.

## Requirements

- Python 3.10 or newer.
- Nmap installed on your system and available in `PATH`.

Windows users can install Nmap from:

https://nmap.org/download.html

After installation, open a new terminal and confirm:

```bash
nmap --version
```

## Installation

```bash
git clone https://github.com/M4H0R4G4/Vulnerability-Scanner-Personalizado.git
cd Vulnerability-Scanner-Personalizado
python -m pip install -r requirements.txt
```

Optional editable install:

```bash
python -m pip install -e .
```

After editable install, the CLI command is available as:

```bash
vulnscan scanme.nmap.org --no-cve
```

## Usage

```bash
# Basic scan, ports 1-1024
python main.py scanme.nmap.org

# Custom port range
python main.py 192.168.1.1 --ports 1-65535

# Faster scan without CVE lookup
python main.py 10.0.0.5 --format html --no-cve

# Use an NVD API key for higher rate limits
python main.py target.com --api-key YOUR_NVD_KEY --format both
```

You can also set the API key with an environment variable:

```bash
set NVD_API_KEY=your-key-here
```

On Linux/macOS:

```bash
export NVD_API_KEY="your-key-here"
```

## CLI Options

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--ports` | `-p` | `1-1024` | Port range or list, such as `22,80,443` |
| `--format` | `-f` | `both` | Report format: `html`, `pdf`, or `both` |
| `--output` | `-o` | auto | Custom output path for single-format reports |
| `--no-cve` | | false | Skip NVD CVE lookup |
| `--api-key` | `-k` | `NVD_API_KEY` | NVD API key |
| `--timeout` | `-t` | `60` | Nmap scan timeout in seconds |
| `--verbose` | `-v` | false | Enable debug logging |

## Project Structure

```text
Vulnerability-Scanner-Personalizado/
├── main.py
├── setup.py
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── LICENSE
├── .gitignore
├── scanner/
│   ├── __init__.py
│   ├── core.py
│   ├── report_html.py
│   └── report_pdf.py
└── tests/
    ├── __init__.py
    └── test_core.py
```

## Running Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Legal Notice

Use this project only on systems you own or have explicit permission to test. Unauthorized scanning can be illegal.

## License

MIT. See `LICENSE` for details.
