#!/usr/bin/env python3
"""
Configuration utilities for Cloudflare ACME WAF Bypass Scanner
"""

import os
from colorama import Fore, Style

# Try to import yaml for config file support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Default config file path
CONFIG_FILE = "config.yaml"


def load_config(config_path=None):
    """Load configuration from YAML file"""
    config_file = config_path or CONFIG_FILE
    
    if not YAML_AVAILABLE:
        return None
    
    if not os.path.exists(config_file):
        return None
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error loading config: {e}{Style.RESET_ALL}")
        return None


def get_api_key_from_config(config, provider):
    """Get API key from config or environment variable"""
    if not config:
        return os.getenv(f'{provider.upper()}_API_KEY')
    
    llm_config = config.get('llm', {})
    provider_config = llm_config.get(provider, {})
    api_key = provider_config.get('api_key', '')
    
    # If empty in config, try environment variable
    if not api_key:
        api_key = os.getenv(f'{provider.upper()}_API_KEY')
    
    return api_key


def get_model_from_config(config, provider):
    """Get model from config"""
    if not config:
        return None
    
    llm_config = config.get('llm', {})
    provider_config = llm_config.get(provider, {})
    return provider_config.get('model')


def get_base_url_from_config(config, provider):
    """Get base URL from config"""
    if not config:
        return None
    
    llm_config = config.get('llm', {})
    provider_config = llm_config.get(provider, {})
    return provider_config.get('base_url')
