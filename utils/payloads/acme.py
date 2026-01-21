#!/usr/bin/env python3
"""
ACME Challenge Payloads
Reference: FearsOff Research (https://fearsoff.org/research/cloudflare-acme)
"""

# Basic ACME Challenge WAF Bypass check
ACME_PAYLOADS = [
    "/.well-known/acme-challenge/",
    "/.well-known/acme-challenge/test",
    "/.well-known/acme-challenge/ae",  # FearsOff technique - append harmless suffix
]
