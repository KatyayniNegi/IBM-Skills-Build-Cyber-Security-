# Automated Web Scanner

## Project Overview
The **Automated Web Scanner** is a Python-based security auditing utility developed as part of the **IBM SkillsBuild Cyber Security 2026** program (conducted by BharatCares). The tool programmatically inspects target websites for HTTP security header deficiencies (such as missing HSTS, CSP, X-Frame-Options) and identifies Cross-Origin Resource Sharing (CORS) policy misconfigurations that could expose sensitive user data to unauthorized domains.

## Dataset / Test Environment
This script is designed to audit live web applications or controlled local testing environments such as:
* [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
* Locally hosted test servers and web applications.

## Technologies Used
* **Python 3.x**
* **Requests Library** (HTTP communication and header inspection)
* **Urllib.parse** (URL parsing and normalization)
* **Argparse** (Command-line interface argument parsing)

## Setup and Installation Instructions
1. Clone or download the project files.
2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the scanner from your terminal:
   ```bash
   python KatyayniNegi_AutomatedWebScanner.py -u https://example.com
   ```

## Key Features
* **Security Header Audit:** Checks for 6 crucial security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`).
* **CORS Flaw Detection:** Tests arbitrary origin injection (`evil.com`, `null`) and evaluates `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers for dangerous misconfigurations.
* **CLI Output:** Color-coded terminal feedback highlighting pass, warning, and critical vulnerabilities.
