#!/usr/bin/env python3
"""
Constants for Cloudflare ACME WAF Bypass Scanner
"""

from colorama import Fore, Style

# Banner
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     {Fore.RED}Cloudflare ACME WAF Bypass Scanner{Fore.CYAN}                       ║
║     {Fore.YELLOW}CVE: Cloudflare Zero-day (Fixed Oct 2025){Fore.CYAN}               ║
║     {Fore.GREEN}Based on FearsOff Research{Fore.CYAN}                              ║
║     {Fore.WHITE}https://fearsoff.org/research/cloudflare-acme{Fore.CYAN}            ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# User agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Framework signatures for detection
FRAMEWORK_SIGNATURES = {
    'spring': ['whitelabel error', 'springframework', 'actuator', 'spring boot'],
    'nextjs': ['__next', '_next', 'nextjs', '__nextdataloading'],
    'php': ['<?php', 'laravel', 'symfony', 'index.php', 'wordpress'],
    'express': ['express', 'node', 'cannot get'],
    'django': ['django', 'csrftoken', 'wsgi'],
    'rails': ['ruby', 'rails', 'actioncontroller'],
}
