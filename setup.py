from setuptools import find_packages, setup


setup(
    name="vuln-scanner-personalizado",
    version="1.0.0",
    description="Personal vulnerability scanner with CVE lookup and HTML/PDF reports",
    author="M4H0R4G4",
    url="https://github.com/M4H0R4G4/Vulnerability-Scanner-Personalizado",
    packages=find_packages(include=["scanner", "scanner.*"]),
    py_modules=["main"],
    python_requires=">=3.10",
    install_requires=[
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
        "reportlab>=4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "vulnscan=main:main",
        ],
    },
)
