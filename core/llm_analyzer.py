#!/usr/bin/env python3
"""
LLM Analyzer - Analyze scan results using various LLM providers
Supports: OpenAI, Anthropic, Ollama, Groq, Gemini
"""

import os
import json
import requests
from colorama import Fore, Style

from utils.config import get_api_key_from_config, get_model_from_config, get_base_url_from_config
from utils.payloads import LLM_ANALYSIS_PROMPT


class LLMAnalyzer:
    """Analyze scan results using LLM (OpenAI/Anthropic/Ollama/Groq/Gemini)"""
    
    SUPPORTED_PROVIDERS = ['openai', 'anthropic', 'ollama', 'groq', 'gemini']
    
    def __init__(self, provider='openai', api_key=None, model=None, base_url=None, config=None):
        self.provider = provider.lower()
        self.config = config
        
        # Get API key from config or parameter or env
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = get_api_key_from_config(config, self.provider)
        
        # Get base URL from config or parameter
        if base_url:
            self.base_url = base_url
        else:
            self.base_url = get_base_url_from_config(config, self.provider)
        
        # Default models per provider
        default_models = {
            'openai': 'gpt-4o',
            'anthropic': 'claude-3-5-sonnet-20241022',
            'ollama': 'llama3.2',
            'groq': 'llama-3.3-70b-versatile',
            'gemini': 'gemini-2.0-flash'
        }
        
        # Get model from config or parameter
        if model:
            self.model = model
        else:
            config_model = get_model_from_config(config, self.provider)
            self.model = config_model or default_models.get(self.provider, 'gpt-4o')
    
    def analyze(self, results, verbose=False):
        """Analyze scan results with LLM"""
        analyses = []
        
        # Filter targets yang perlu dianalisis
        targets_to_analyze = [r for r in results if r.get('waf_bypass') or r.get('findings')]
        total = len(targets_to_analyze)
        
        if total > 0:
            print(f"{Fore.CYAN}[*] Analyzing {total} target(s) with AI...{Style.RESET_ALL}")
        
        for i, result in enumerate(targets_to_analyze, 1):
            if verbose:
                print(f"\n{Fore.CYAN}[*] [{i}/{total}] Analyzing: {result['target']}{Style.RESET_ALL}")
            else:
                # Progress indicator sederhana
                print(f"  [{i}/{total}] {result['target'][:50]}...", end='\r')
            
            analysis = self._analyze_single(result)
            if analysis:
                analyses.append({
                    'target': result['target'],
                    'analysis': analysis
                })
        
        if not verbose and total > 0:
            print()  # Newline setelah progress
        
        return analyses
    
    def _analyze_single(self, result):
        """Analyze single target result"""
        # Prepare findings JSON
        findings_json = json.dumps(result.get('findings', []), indent=2)
        
        # Get origin IPs
        origin_ips = result.get('origin_ips', [])
        origin_ips_str = ", ".join([ip.get('ip', 'N/A') for ip in origin_ips]) if origin_ips else "Not found"
        
        # Build prompt
        prompt = LLM_ANALYSIS_PROMPT.format(
            target=result['target'],
            cloudflare=result.get('cloudflare', False),
            waf_bypass=result.get('waf_bypass', False),
            framework=result.get('framework', 'unknown'),
            origin_ips=origin_ips_str,
            findings_json=findings_json
        )
        
        try:
            if self.provider == 'openai':
                return self._call_openai(prompt)
            elif self.provider == 'anthropic':
                return self._call_anthropic(prompt)
            elif self.provider == 'ollama':
                return self._call_ollama(prompt)
            elif self.provider == 'groq':
                return self._call_groq(prompt)
            elif self.provider == 'gemini':
                return self._call_gemini(prompt)
            else:
                print(f"{Fore.RED}[!] Unsupported LLM provider: {self.provider}{Style.RESET_ALL}")
                return None
        except Exception as e:
            print(f"{Fore.RED}[!] LLM analysis error: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _call_openai(self, prompt):
        """Call OpenAI API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] OpenAI API key not found. Set OPENAI_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an expert security researcher and penetration tester."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 4000
        }
        
        url = self.base_url or "https://api.openai.com/v1/chat/completions"
        
        resp = requests.post(url, headers=headers, json=data, timeout=60)
        resp.raise_for_status()
        
        return resp.json()['choices'][0]['message']['content']
    
    def _call_anthropic(self, prompt):
        """Call Anthropic Claude API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] Anthropic API key not found. Set ANTHROPIC_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        data = {
            "model": self.model,
            "max_tokens": 4000,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        url = self.base_url or "https://api.anthropic.com/v1/messages"
        
        try:
            resp = requests.post(url, headers=headers, json=data, timeout=120)
            
            if resp.status_code != 200:
                error_detail = resp.text[:500] if resp.text else "No details"
                print(f"{Fore.RED}[!] Anthropic API Error {resp.status_code}: {error_detail}{Style.RESET_ALL}")
                return None
            
            return resp.json()['content'][0]['text']
        except Exception as e:
            print(f"{Fore.RED}[!] Anthropic request failed: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _call_ollama(self, prompt):
        """Call local Ollama API"""
        url = self.base_url or "http://localhost:11434/api/generate"
        
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        resp = requests.post(url, json=data, timeout=120)
        resp.raise_for_status()
        
        return resp.json()['response']
    
    def _call_groq(self, prompt):
        """Call Groq API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] Groq API key not found. Set GROQ_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an expert security researcher and penetration tester."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 4000
        }
        
        url = self.base_url or "https://api.groq.com/openai/v1/chat/completions"
        
        resp = requests.post(url, headers=headers, json=data, timeout=60)
        resp.raise_for_status()
        
        return resp.json()['choices'][0]['message']['content']
    
    def _call_gemini(self, prompt):
        """Call Google Gemini API"""
        if not self.api_key:
            print(f"{Fore.YELLOW}[!] Gemini API key not found. Set GEMINI_API_KEY env var or use --api-key{Style.RESET_ALL}")
            return None
        
        # Gemini API endpoint format
        base_url = self.base_url or "https://generativelanguage.googleapis.com/v1beta/models"
        url = f"{base_url}/{self.model}:generateContent?key={self.api_key}"
        
        headers = {
            "Content-Type": "application/json"
        }
        
        data = {
            "contents": [{
                "parts": [{
                    "text": f"You are an expert security researcher and penetration tester.\n\n{prompt}"
                }]
            }],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 8192
            }
        }
        
        try:
            resp = requests.post(url, headers=headers, json=data, timeout=120)
            
            if resp.status_code != 200:
                error_detail = resp.text[:500] if resp.text else "No details"
                print(f"{Fore.RED}[!] Gemini API Error {resp.status_code}: {error_detail}{Style.RESET_ALL}")
                return None
            
            result = resp.json()
            return result['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            print(f"{Fore.RED}[!] Gemini request failed: {str(e)}{Style.RESET_ALL}")
            return None
    
    def print_analysis(self, analyses, verbose=False):
        """Print LLM analysis results (only if verbose)"""
        if verbose:
            for analysis in analyses:
                print(f"\n{Fore.CYAN}{'='*65}")
                print(f"  LLM ANALYSIS: {analysis['target']}")
                print(f"{'='*65}{Style.RESET_ALL}\n")
                print(analysis['analysis'])
    
    def save_analysis(self, analyses, filename):
        """Save analysis to file"""
        # Buat direktori jika belum ada
        output_dir = os.path.dirname(filename)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        with open(filename, 'w', encoding='utf-8') as f:
            for analysis in analyses:
                f.write(f"# Analysis: {analysis['target']}\n")
                f.write(f"{'='*65}\n\n")
                f.write(analysis['analysis'])
                f.write(f"\n\n{'='*65}\n\n")
        
        print(f"\n{Fore.GREEN}[+] Analysis saved to: {filename}{Style.RESET_ALL}")
