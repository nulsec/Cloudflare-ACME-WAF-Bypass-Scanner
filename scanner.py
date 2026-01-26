#!/usr/bin/env python3
"""
Cloudflare ACME Challenge WAF Bypass Scanner
Based on FearsOff Research: https://fearsoff.org/research/cloudflare-acme

Vulnerability: /.well-known/acme-challenge/{token} bypasses Cloudflare WAF
- Requests to this path reach origin directly, bypassing customer WAF rules
- Can be chained with framework-specific vulnerabilities
- Fixed by Cloudflare on October 27, 2025

For authorized ethical hacking and security testing only!
"""

import argparse
import time
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Import modules
from utils.config import load_config
from utils.constants import BANNER
from core.scanner import CloudflareScanner
from core.oast import OASTClient, SimpleOASTServer
from core.poc_generator import POCGenerator
from core.llm_analyzer import LLMAnalyzer


def main():
    print(BANNER)
    
    # Load configuration from config.yaml
    config = load_config()
    if config:
        print(f"{Fore.GREEN}[+] Loaded configuration from config.yaml{Style.RESET_ALL}")
    
    parser = argparse.ArgumentParser(
        description='Cloudflare ACME Challenge WAF Bypass Scanner - Based on FearsOff Research',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u https://target.com
  python scanner.py -l targets.txt -t 5 -o results.json
  python scanner.py -u https://target.com --token "yMnWOcR2yv..." -v
  
  # Generate POC exploits
  python scanner.py -l targets.txt --poc
  
  # Analyze with LLM (uses config.yaml if available)
  python scanner.py -l targets.txt --analyze
  python scanner.py -l targets.txt --analyze --llm openai --api-key sk-xxx
  python scanner.py -l targets.txt --analyze --llm ollama --model llama3.2
  
  # Use custom config file
  python scanner.py -l targets.txt --config my_config.yaml --analyze
  
  # OAST (Out-of-band Application Security Testing)
  # Enable OAST to detect blind vulnerabilities (SSRF, XSS, RCE, etc.)
  python scanner.py -u https://target.com --oast
  
  # Use specific Interactsh server
  python scanner.py -u https://target.com --oast --oast-server interact.sh
  
  # Use custom callback domain (your own server)
  python scanner.py -u https://target.com --oast --oast-domain your-domain.com
  
  # Start your own OAST callback server
  python scanner.py --oast-server-mode --oast-port 8080
  
Reference: https://fearsoff.org/research/cloudflare-acme
        """
    )
    parser.add_argument('-u', '--url', help='Single target URL')
    parser.add_argument('-l', '--list', help='File containing list of targets')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads (default: 10)')
    parser.add_argument('-T', '--timeout', type=int, help='Request timeout (default: 10)')
    parser.add_argument('-d', '--delay', type=float, help='Delay between requests (default: 0)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--token', help='Custom ACME challenge token (default: random)')
    parser.add_argument('--config', help='Path to config file (default: config.yaml)')
    
    # POC Generation arguments
    parser.add_argument('--poc', action='store_true', help='Generate exploit POC files')
    parser.add_argument('--poc-dir', help='Output directory for POC files (default: pocs)')
    
    # LLM Analysis arguments
    parser.add_argument('--analyze', action='store_true', help='Analyze results with LLM')
    parser.add_argument('--llm', choices=['openai', 'anthropic', 'ollama', 'groq', 'gemini'], 
                        help='LLM provider (default from config or openai)')
    parser.add_argument('--api-key', help='API key for LLM provider (overrides config)')
    parser.add_argument('--model', help='LLM model to use (overrides config)')
    parser.add_argument('--llm-url', help='Custom LLM API URL (overrides config)')
    parser.add_argument('--analysis-output', help='Save LLM analysis to file')
    
    # OAST arguments
    parser.add_argument('--oast', action='store_true', help='Enable OAST (Out-of-band) testing for blind vulns')
    parser.add_argument('--oast-server', help='Interactsh server (default: random from pool)')
    parser.add_argument('--oast-domain', help='Custom callback domain (your own OAST server)')
    parser.add_argument('--oast-poll', type=int, default=5, help='OAST polling interval in seconds (default: 5)')
    parser.add_argument('--oast-wait', type=int, default=30, help='Wait time for OAST callbacks after scan (default: 30)')
    parser.add_argument('--oast-server-mode', action='store_true', help='Start local OAST callback server')
    parser.add_argument('--oast-port', type=int, default=8080, help='OAST server port (default: 8080)')
    
    args = parser.parse_args()
    
    # Load config from custom path if specified
    if args.config:
        config = load_config(args.config)
        if config:
            print(f"{Fore.GREEN}[+] Loaded configuration from {args.config}{Style.RESET_ALL}")
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Get scanner settings from config or args (args override config)
    scanner_config = config.get('scanner', {}) if config else {}
    oast_config = config.get('oast', {}) if config else {}
    
    # ============================================
    # OAST SERVER MODE - Start local callback server
    # ============================================
    if args.oast_server_mode:
        print(f"{Fore.CYAN}[*] Starting OAST callback server...{Style.RESET_ALL}")
        
        oast_server = SimpleOASTServer(
            host='0.0.0.0',
            http_port=args.oast_port
        )
        
        oast_server.start()
        
        try:
            print(f"{Fore.CYAN}[*] Server running. Press Ctrl+C to stop.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Point your domain to this server's IP{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Then use: --oast --oast-domain <your-domain>{Style.RESET_ALL}\n")
            
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Stopping OAST server...{Style.RESET_ALL}")
            oast_server.stop()
            
            # Print received interactions
            interactions = oast_server.get_interactions()
            if interactions:
                print(f"\n{Fore.GREEN}[+] Received {len(interactions)} interaction(s):{Style.RESET_ALL}")
                for i, interaction in enumerate(interactions, 1):
                    print(f"  {i}. [{interaction['protocol']}] {interaction['path']} from {interaction['remote-address']}")
        
        return
    
    # ============================================
    # NORMAL MODE (with optional OAST)
    # ============================================
    if not args.url and not args.list:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Please specify a target (-u) or target list (-l){Style.RESET_ALL}")
        return
    
    targets = []
    
    if args.url:
        targets.append(args.url)
    
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.list}{Style.RESET_ALL}")
            return
    
    # Remove duplicates
    targets = list(set(targets))
    
    # Initialize OAST client if enabled
    oast_client = None
    if args.oast or oast_config.get('enabled', False):
        print(f"\n{Fore.CYAN}[*] Initializing OAST (Out-of-band) testing...{Style.RESET_ALL}")
        
        oast_client = OASTClient(
            server=args.oast_server or oast_config.get('server'),
            custom_domain=args.oast_domain or oast_config.get('domain'),
            poll_interval=args.oast_poll or oast_config.get('poll_interval', 5)
        )
        
        if oast_client.register():
            oast_client.start_polling()
        else:
            print(f"{Fore.YELLOW}[!] OAST registration failed, continuing without OAST{Style.RESET_ALL}")
            oast_client = None
    
    scanner = CloudflareScanner(
        timeout=args.timeout if args.timeout is not None else scanner_config.get('timeout', 10),
        threads=args.threads if args.threads is not None else scanner_config.get('threads', 10),
        delay=args.delay if args.delay is not None else scanner_config.get('delay', 0),
        verbose=args.verbose or scanner_config.get('verbose', False),
        token=args.token,
        oast_client=oast_client
    )
    
    try:
        scanner.scan_targets(targets)
        
        # Wait for OAST callbacks if enabled
        if oast_client:
            wait_time = args.oast_wait or oast_config.get('wait_time', 30)
            print(f"\n{Fore.CYAN}[*] Waiting {wait_time}s for OAST callbacks...{Style.RESET_ALL}")
            
            for i in range(wait_time):
                time.sleep(1)
                if (i + 1) % 10 == 0:
                    triggered = oast_client.get_triggered_payloads()
                    print(f"    {i+1}s - {len(triggered)} callback(s) received")
            
            oast_client.stop_polling()
            
            # Add OAST findings to results
            triggered = oast_client.get_triggered_payloads()
            if triggered:
                print(f"\n{Fore.RED}[!!!] OAST VULNERABILITIES DETECTED:{Style.RESET_ALL}")
                for t in triggered:
                    print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} {t['target']}")
                    print(f"      Type: {t['payload_type']}")
                    print(f"      Callback received from: {t['interaction'].get('remote-address', 'N/A')}")
                    
                    # Add to scanner results
                    for result in scanner.results:
                        if result['target'] == t['target']:
                            result['findings'].append({
                                'type': f"OAST: {t['payload_type']}",
                                'vulnerable': True,
                                'critical': True,
                                'callback_received': True,
                                'interaction': t['interaction']
                            })
            
            # Print OAST summary
            summary = oast_client.get_summary()
            print(f"\n{Fore.CYAN}[*] OAST Summary:{Style.RESET_ALL}")
            print(f"    Callback Domain: {summary['callback_domain']}")
            print(f"    Total Payloads Sent: {summary['total_payloads']}")
            print(f"    Callbacks Received: {Fore.RED if summary['triggered_payloads'] > 0 else Fore.GREEN}{summary['triggered_payloads']}{Style.RESET_ALL}")
        
        scanner.print_summary()
        
        # Get output settings from config
        output_config = config.get('output', {}) if config else {}
        
        output_file = args.output or output_config.get('results_file')
        if output_file:
            scanner.save_results(output_file)
        
        # Get POC settings from config
        poc_config = config.get('poc', {}) if config else {}
        
        # Generate POC exploits
        if args.poc or poc_config.get('enabled', False):
            print(f"\n{Fore.CYAN}[*] Generating exploit POCs...{Style.RESET_ALL}")
            poc_gen = POCGenerator(scanner.results)
            poc_dir = args.poc_dir or poc_config.get('output_dir', 'pocs')
            generated_files = poc_gen.generate_all(poc_dir)
            print(f"\n{Fore.GREEN}[+] Generated {len(generated_files)} POC files in '{poc_dir}/' directory{Style.RESET_ALL}")
        
        # LLM Analysis
        if args.analyze:
            # Get LLM settings from config
            llm_config = config.get('llm', {}) if config else {}
            
            # Provider: args > config > default
            llm_provider = args.llm or llm_config.get('provider', 'openai')
            
            print(f"\n{Fore.CYAN}[*] Starting LLM analysis with {llm_provider}...{Style.RESET_ALL}")
            
            analyzer = LLMAnalyzer(
                provider=llm_provider,
                api_key=args.api_key,
                model=args.model,
                base_url=args.llm_url,
                config=config
            )
            
            analyses = analyzer.analyze(scanner.results, verbose=args.verbose)
            
            if analyses:
                # Always save to file (default: reports/analysis.md)
                analysis_output = args.analysis_output or output_config.get('analysis_file', 'reports/analysis.md')
                analyzer.save_analysis(analyses, analysis_output)
                
                # Only print to terminal if verbose
                if args.verbose:
                    analyzer.print_analysis(analyses, verbose=True)
                else:
                    print(f"{Fore.CYAN}[*] {len(analyses)} target(s) analyzed. Details saved to: {analysis_output}{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        if oast_client:
            oast_client.stop_polling()
        scanner.print_summary()


if __name__ == '__main__':
    main()
