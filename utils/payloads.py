#!/usr/bin/env python3
"""
Payloads and templates for Cloudflare ACME WAF Bypass Scanner

This file redirects to the modular payloads package for backward compatibility.
The payloads have been split into multiple files for better maintainability:

utils/payloads/
├── __init__.py       # Main module with all exports
├── acme.py           # Basic ACME challenge payloads
├── actuator.py       # Spring Boot Actuator payloads
├── cloudflare.py     # Cloudflare-specific WAF bypass
├── graphql.py        # GraphQL introspection payloads
├── headers.py        # HTTP headers for WAF bypass
├── injection.py      # XSS, SQLi, SSTI, Command Injection
├── log4shell.py      # Log4Shell/JNDI payloads
├── nextjs.py         # Next.js RSC RCE (CVE-2024-34351, CVE-2025-55182, CVE-2025-66478)
├── sensitive_paths.py # Admin panel and sensitive paths
├── ssrf.py           # SSRF payloads
├── templates.py      # POC templates
├── traversal.py      # Path traversal and LFI
└── xxe.py            # XXE payloads

References:
- PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
- SecLists (https://github.com/danielmiessler/SecLists)
- HackTricks (https://book.hacktricks.wiki)
- FearsOff Research (https://fearsoff.org/research/cloudflare-acme)
- Assetnote Research (https://assetnote.io/blog/nextjs-and-the-corrupt-middleware)
"""

# Import everything from the payloads package for backward compatibility
from utils.payloads import (
    # ACME
    ACME_PAYLOADS,
    
    # Cloudflare
    CF_WAF_BYPASS_PAYLOADS,
    CF_CACHE_POISON_PAYLOADS,
    CF_BYPASS_PATHS,
    CF_SMUGGLING_PAYLOADS,
    CF_WORKERS_BYPASS,
    
    # Traversal
    PATH_TRAVERSAL_PAYLOADS,
    PHP_LFI_PAYLOADS,
    
    # Actuator
    ACTUATOR_PAYLOADS,
    
    # Next.js
    NEXTJS_PAYLOADS,
    NEXTJS_RSC_RCE_PAYLOADS,
    NEXTJS_RSC_BYPASS_HEADERS,
    NEXTJS_RSC_POST_PAYLOADS,
    
    # GraphQL
    GRAPHQL_PAYLOADS,
    
    # Sensitive Paths
    SENSITIVE_PATHS,
    
    # Injection
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SSTI_PAYLOADS,
    CMD_INJECTION_PAYLOADS,
    
    # XXE
    XXE_PAYLOADS,
    
    # SSRF
    SSRF_PAYLOADS,
    
    # Log4Shell
    LOG4SHELL_PAYLOADS,
    
    # Headers
    HOST_HEADER_PAYLOADS,
    HTTP2_BYPASS_PAYLOADS,
    RATE_LIMIT_BYPASS_HEADERS,
    BYPASS_HEADERS,
    
    # Templates
    POC_TEMPLATES,
    LLM_ANALYSIS_PROMPT,
)

__all__ = [
    # ACME & Cloudflare
    'ACME_PAYLOADS',
    'CF_WAF_BYPASS_PAYLOADS',
    'CF_CACHE_POISON_PAYLOADS',
    'CF_BYPASS_PATHS',
    'CF_SMUGGLING_PAYLOADS',
    'CF_WORKERS_BYPASS',
    
    # Web Application
    'PATH_TRAVERSAL_PAYLOADS',
    'PHP_LFI_PAYLOADS',
    'ACTUATOR_PAYLOADS',
    'NEXTJS_PAYLOADS',
    'NEXTJS_RSC_RCE_PAYLOADS',
    'NEXTJS_RSC_BYPASS_HEADERS',
    'NEXTJS_RSC_POST_PAYLOADS',
    'GRAPHQL_PAYLOADS',
    'SENSITIVE_PATHS',
    
    # Injection
    'XSS_PAYLOADS',
    'SQLI_PAYLOADS',
    'CMD_INJECTION_PAYLOADS',
    'SSTI_PAYLOADS',
    'XXE_PAYLOADS',
    'SSRF_PAYLOADS',
    'LOG4SHELL_PAYLOADS',
    
    # Headers
    'BYPASS_HEADERS',
    'HOST_HEADER_PAYLOADS',
    'HTTP2_BYPASS_PAYLOADS',
    'RATE_LIMIT_BYPASS_HEADERS',
    
    # Templates
    'POC_TEMPLATES',
    'LLM_ANALYSIS_PROMPT',
]
