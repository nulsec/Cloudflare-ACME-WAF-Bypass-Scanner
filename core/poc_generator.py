#!/usr/bin/env python3
"""
POC Generator - Auto-generate exploit POC from scan results
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
