#!/usr/bin/env python3
"""
Automated Web Security Scanner
Author: Katyayni Negi
Context: IBM SkillsBuild Cyber Security 2026 (BharatCares)
Description: Audits target websites for secure HTTP headers and CORS policy misconfigurations.
"""

import sys
import argparse
import requests
from urllib.parse import urlparse

# ANSI Color Codes for Terminal Output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

class WebSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        if not self.parsed_url.scheme:
            self.target_url = "https://" + target_url
            self.parsed_url = urlparse(self.target_url)
        
        self.headers_to_check = {
            "Strict-Transport-Security": "HSTS protects against man-in-the-middle attacks by forcing HTTPS.",
            "Content-Security-Policy": "CSP mitigates Cross-Site Scripting (XSS) and data injection attacks.",
            "X-Frame-Options": "Protects users against Clickjacking attacks.",
            "X-Content-Type-Options": "Prevents MIME-sniffing attacks by enforcing declared content types.",
            "X-XSS-Protection": "Enables browser-level XSS filtering mechanisms.",
            "Referrer-Policy": "Controls how referrer information is shared with other sites."
        }

    def scan_secure_headers(self):
        print(f"\n{BLUE}[+] Starting Security Header Analysis for: {self.target_url}{RESET}")
        try:
            response = requests.get(self.target_url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            print(f"[*] Final URL after redirects: {response.url}")
            print(f"[*] HTTP Status Code: {response.status_code}\n")
            
            results = {"present": [], "missing": []}
            
            for header, description in self.headers_to_check.items():
                if header in headers:
                    print(f"  {GREEN}[PASS] {header} is present.{RESET}")
                    print(f"         Value: {headers.get(header)}")
                    results["present"].append((header, headers.get(header)))
                else:
                    print(f"  {RED}[FAIL] {header} is missing!{RESET}")
                    print(f"         Risk: {description}")
                    results["missing"].append(header)
            
            return results
        except requests.exceptions.RequestException as e:
            print(f"{RED}[ERROR] Connection failed: {e}{RESET}")
            return None

    def scan_cors_flaws(self):
        print(f"\n{BLUE}[+] Starting CORS Policy Misconfiguration Assessment...{RESET}")
        test_origins = [
            "https://evil.com",
            "null",
            f"https://{self.parsed_url.netloc}.evil.com"
        ]
        
        vulnerabilities_found = False
        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                response = requests.get(self.target_url, headers=headers, timeout=10)
                
                acao = response.headers.get("Access-Control-Allow-Origin")
                acac = response.headers.get("Access-Control-Allow-Credentials")
                
                if acao:
                    print(f"[*] Testing Origin: {origin}")
                    print(f"    Access-Control-Allow-Origin: {acao}")
                    print(f"    Access-Control-Allow-Credentials: {acac}")
                    
                    if acao == "*" or acao == origin:
                        if acac == "true" and acao == "*":
                            print(f"  {RED}[CRITICAL] Wildcard (*) combined with Allow-Credentials=true! Highly vulnerable CORS configuration.{RESET}")
                            vulnerabilities_found = True
                        elif acao == origin:
                            print(f"  {YELLOW}[WARNING] Origin reflection detected ({origin}). Potential arbitrary origin trust if credentials are allowed.{RESET}")
                            vulnerabilities_found = True
                        else:
                            print(f"  {YELLOW}[INFO] Permissive CORS policy detected (Wildcard * without credentials).{RESET}")
            except requests.exceptions.RequestException as e:
                print(f"{RED}[ERROR] CORS check failed for origin {origin}: {e}{RESET}")
        
        if not vulnerabilities_found:
            print(f"  {GREEN}[PASS] No critical CORS misconfigurations detected with tested origins.{RESET}")

def main():
    parser = argparse.ArgumentParser(description="Automated Web Security Scanner for Headers and CORS")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan (e.g., https://example.com)")
    args = parser.parse_args()
    
    print("=" * 60)
    print("   AUTOMATED WEB SECURITY SCANNER - IBM SKILLSBUILD 2026")
    print("   Author: Katyayni Negi")
    print("=" * 60)
    
    scanner = WebSecurityScanner(args.url)
    scanner.scan_secure_headers()
    scanner.scan_cors_flaws()
    print("\n" + "=" * 60)
    print("   SCAN COMPLETED SUCCESSFULLY")
    print("=" * 60)

if __name__ == "__main__":
    main()
