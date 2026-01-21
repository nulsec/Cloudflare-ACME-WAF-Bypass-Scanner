#!/usr/bin/env python3
"""
Payloads Module - Organized WAF Bypass Payloads
Split into multiple files for better maintainability
"""

# ACME & Cloudflare specific
from .acme import ACME_PAYLOADS
from .cloudflare import (
    CF_WAF_BYPASS_PAYLOADS,
    CF_CACHE_POISON_PAYLOADS,
    CF_BYPASS_PATHS,
    CF_SMUGGLING_PAYLOADS,
    CF_WORKERS_BYPASS,
)

# Web Application Payloads
from .traversal import PATH_TRAVERSAL_PAYLOADS, PHP_LFI_PAYLOADS
from .actuator import ACTUATOR_PAYLOADS
from .nextjs import (
    NEXTJS_PAYLOADS,
    NEXTJS_RSC_RCE_PAYLOADS,
    NEXTJS_RSC_BYPASS_HEADERS,
    NEXTJS_RSC_POST_PAYLOADS,
)
from .graphql import GRAPHQL_PAYLOADS
from .sensitive_paths import SENSITIVE_PATHS

# Injection Payloads
from .injection import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    CMD_INJECTION_PAYLOADS,
    SSTI_PAYLOADS,
)
from .xxe import XXE_PAYLOADS
from .ssrf import SSRF_PAYLOADS
from .log4shell import LOG4SHELL_PAYLOADS

# Headers
from .headers import (
    BYPASS_HEADERS,
    HOST_HEADER_PAYLOADS,
    HTTP2_BYPASS_PAYLOADS,
    RATE_LIMIT_BYPASS_HEADERS,
)

# Templates
from .templates import POC_TEMPLATES, LLM_ANALYSIS_PROMPT

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
