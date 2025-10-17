#!/usr/bin/env python3
# SFUZZ - Advanced Security Fuzzing & Scanning Platform
# Author: Suman Das
# License: MIT

import argparse, os, sys, json, time, socket, subprocess, shutil, re
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from random import sample, choice
import requests
from colorama import init as colorama_init, Fore, Style
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs

# Optional imports with graceful fallbacks
try:
    import dns.resolver
except ImportError:
    dns = None
    print(f"{Fore.YELLOW}[!] dnspython not installed. DNS resolution may be limited.{Style.RESET_ALL}")

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# Silencing insecure warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tool metadata
__version__ = "1.0.0"
__author__ = "Suman Das"
__license__ = "MIT"

colorama_init(autoreset=True)

BANNER = rf"""
{Fore.CYAN}
 ███████╗███████╗██╗   ██╗███████╗███████╗
 ██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
 ███████╗█████╗  ██║   ██║  ███╔╝   ███╔╝ 
 ╚════██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
 ███████║██      ╚██████╔╝███████╗███████╗
 ╚══════╝╚═      ╚═════╝ ╚══════╝╚══════╝
{Style.RESET_ALL}
        Advanced Security Fuzzing & Scanning Platform v{__version__}
    ──────────────────────────────────────────────────────────
    Phases: {Fore.GREEN}•{Style.RESET_ALL} Recon {Fore.GREEN}•{Style.RESET_ALL} Scanning {Fore.GREEN}•{Style.RESET_ALL} Enumeration {Fore.GREEN}•{Style.RESET_ALL} Vulnerability {Fore.GREEN}•{Style.RESET_ALL} Exploitation
    AI Modes: {Fore.CYAN}•{Style.RESET_ALL} Fast {Fore.CYAN}•{Style.RESET_ALL} Smart {Fore.CYAN}•{Style.RESET_ALL} Aggressive {Fore.CYAN}•{Style.RESET_ALL} Deep
    ──────────────────────────────────────────────────────────
"""
print(BANNER)

# ---------------------------
# CLI Arguments
# ---------------------------
parser = argparse.ArgumentParser(prog="sfuzz", description="SFUZZ - Advanced Security Fuzzing & Scanning Platform")
parser.add_argument("-d","--domain", help="Target domain (single)")
parser.add_argument("-u","--url", help="Single URL to test")
parser.add_argument("-i","--input", help="Input file with domains/URLs")
parser.add_argument("-w","--wordlist", help="Subdomain wordlist for active bruteforce")
parser.add_argument("-l","--levels", type=int, default=3, help="Recursion depth for active bruteforce (default 3)")
parser.add_argument("--workers", type=int, default=100, help="Concurrent workers (default 100)")
parser.add_argument("--timeout", type=float, default=3.0, help="Timeout in seconds (default 3.0)")
parser.add_argument("--no-color", action="store_true", help="Disable colors")
parser.add_argument("-o","--output", help="Output file")
parser.add_argument("--json-output", help="JSON output file")
parser.add_argument("--verbose", action="store_true", help="Verbose logging")

# Scanning Phases
parser.add_argument("--recon", action="store_true", help="Full reconnaissance")
parser.add_argument("--passive", action="store_true", help="Passive intelligence gathering")
parser.add_argument("--active", action="store_true", help="Active subdomain enumeration")
parser.add_argument("--subdomains", action="store_true", help="Find subdomains (passive + active)")
parser.add_argument("--scan", action="store_true", help="Full scanning phase")
parser.add_argument("--portscan", action="store_true", help="Port scanning")
parser.add_argument("--ports", help="Ports to scan (default: top 1000)")
parser.add_argument("--dirscan", action="store_true", help="Directory and file scanning")
parser.add_argument("--dir-wordlist", help="Directory wordlist")
parser.add_argument("--crawl", action="store_true", help="Website crawling")

# Vulnerability Assessment
parser.add_argument("--vuln-scan", action="store_true", help="Vulnerability scanning")
parser.add_argument("--takeover", action="store_true", help="Subdomain takeover check")
parser.add_argument("--headers", action="store_true", help="Security headers analysis")
parser.add_argument("--xss-scan", action="store_true", help="XSS vulnerability scanning")
parser.add_argument("--sqli-scan", action="store_true", help="SQL injection scanning")
parser.add_argument("--lfi-scan", action="store_true", help="Local File Inclusion scanning")
parser.add_argument("--nuclei-scan", action="store_true", help="Nuclei vulnerability scanning")
parser.add_argument("--param-scan", action="store_true", help="Parameter discovery and fuzzing")
parser.add_argument("--param", help="Test specific parameter (requires --url)")
parser.add_argument("--full-param-scan", action="store_true", help="Thorough parameter discovery and testing")

# Technology Detection
parser.add_argument("--tech-detect", action="store_true", help="Technology stack detection")
parser.add_argument("--full-tech-scan", action="store_true", help="Comprehensive technology detection")

# AI Configuration
parser.add_argument("--ai-mode", default="smart", choices=["off", "fast", "smart", "aggressive", "deep"],
                    help="AI mode: off|fast|smart|aggressive|deep (default: smart)")
parser.add_argument("--ai-recon", action="store_true", help="AI-enhanced reconnaissance")
parser.add_argument("--ai-scan", action="store_true", help="AI-enhanced scanning")
parser.add_argument("--ai-vuln", action="store_true", help="AI-enhanced vulnerability assessment")
parser.add_argument("--no-ai-download", action="store_true", help="Skip auto AI model download")

# Advanced Options
parser.add_argument("--full-scan", action="store_true", help="Complete penetration test (all phases)")
parser.add_argument("--quick", action="store_true", help="Quick scan (essential checks only)")
parser.add_argument("--stealth", action="store_true", help="Stealth mode (slower, less detectable)")
parser.add_argument("--rate", type=float, default=5.0, help="Maximum requests per second (default: 5.0)")
parser.add_argument("--resume", action="store_true", help="Resume previous scan from checkpoint")
parser.add_argument("--state-file", default=".sfuzz_state.json", help="Checkpoint file for scan resumption (default: .sfuzz_state.json)")

args = parser.parse_args()

if args.no_color:
    Fore.GREEN = Fore.YELLOW = Fore.RED = Fore.CYAN = Fore.MAGENTA = Fore.WHITE = Fore.RESET = ""
    Style.RESET_ALL = ""

# Auto-enable phases based on shortcuts
if args.full_scan:
    args.recon = args.scan = args.vuln_scan = True
    args.nuclei_scan = True
    args.param_scan = True
    args.passive = args.active = True
    args.portscan = args.dirscan = args.crawl = True
    args.takeover = args.headers = True
    args.xss_scan = args.sqli_scan = args.lfi_scan = True
    args.tech_detect = args.full_tech_scan = True
    args.ai_mode = "deep"
    args.ai_recon = args.ai_scan = args.ai_vuln = True

if args.quick:
    args.subdomains = args.portscan = True
    args.ai_mode = "fast"
    
if args.recon:
    args.passive = args.active = True
    
if args.scan:
    args.portscan = args.dirscan = args.crawl = True

if args.vuln_scan:
    args.nuclei_scan = args.takeover = args.headers = True
    args.xss_scan = args.sqli_scan = args.lfi_scan = True

if args.full_tech_scan:
    args.tech_detect = True

# Auto-enable AI for specific phases if AI mode is not off
if args.ai_mode != "off":
    if not any([args.ai_recon, args.ai_scan, args.ai_vuln]):
        args.ai_recon = args.ai_scan = args.ai_vuln = True

# ---------------------------
# Configuration
# ---------------------------
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
WORDLISTS_SUB = os.path.join(SCRIPT_DIR, "wordlists", "subdomains")
WORDLISTS_DIRS = os.path.join(SCRIPT_DIR, "wordlists", "dirs")
AI_MODELS_DIR = os.path.join(SCRIPT_DIR, "ai_models")
AI_SETUP_FLAG = os.path.join(SCRIPT_DIR, ".ai_setup_done")

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 22, 21, 25, 53, 110, 143, 993, 995, 
                3306, 3389, 5432, 27017, 6379, 11211, 9200, 9300, 5601]

# Global sets for duplicate tracking
discovered_subdomains = set()
discovered_urls = set()
discovered_paths = set()
live_subdomains = set()
live_urls = set()
technology_stack = {}

color_lock = threading.Lock()

# ---------------------------
# ADVANCED AI SUBDOMAIN ANALYSIS
# ---------------------------
class AISubdomainAnalyzer:
    def __init__(self):
        self.patterns = {}
        self.discovered = set()
        self.industry_patterns = {}
        self.common_services = {
            'api': ['api', 'apis', 'rest', 'gw', 'gateway'],
            'dev': ['dev', 'development', 'staging', 'test', 'uat', 'qa'],
            'admin': ['admin', 'administrator', 'manage', 'manager', 'portal'],
            'cdn': ['cdn', 'static', 'assets', 'media', 'content'],
            'auth': ['auth', 'login', 'sso', 'identity', 'accounts'],
            'geo': ['us', 'eu', 'asia', 'in', 'uk', 'au']
        }
    
    def learn_patterns(self, domain, known_subdomains):
        """Learn patterns from known subdomains using AI"""
        if not ai_system.ollama_available:
            return
        
        prompt = f"""
        Analyze these subdomains for {domain}:
        {list(known_subdomains)[:50]}
        
        Identify:
        1. Common naming patterns (format: TYPE: pattern)
        2. Environment indicators (dev, staging, prod)
        3. Service patterns (api, cdn, mail)
        4. Geographic patterns (us, eu, asia)
        5. Department patterns (sales, marketing)
        
        Return only patterns, one per line:
        PATTERN: <pattern>
        CONFIDENCE: <0-100>
        CATEGORY: <env|service|geo|dept>
        EXAMPLES: <matching examples>
        """
        
        response = ai_system.query_ollama(prompt)
        if response:
            self.patterns[domain] = self._parse_patterns(response)
    
    def _parse_patterns(self, response):
        """Parse AI response into structured patterns"""
        patterns = []
        current = {}
        
        for line in response.splitlines():
            line = line.strip()
            if not line:
                if current:
                    patterns.append(current)
                    current = {}
                continue
                
            if line.startswith('PATTERN:'):
                current['pattern'] = line.split(':', 1)[1].strip()
            elif line.startswith('CONFIDENCE:'):
                try:
                    current['confidence'] = int(line.split(':', 1)[1].strip())
                except:
                    current['confidence'] = 50
            elif line.startswith('CATEGORY:'):
                current['category'] = line.split(':', 1)[1].strip().lower()
            elif line.startswith('EXAMPLES:'):
                current['examples'] = [x.strip() for x in line.split(':', 1)[1].strip().split(',')]
        
        if current:
            patterns.append(current)
        
        return patterns
    
    def generate_targeted_wordlist(self, domain, base_words):
        """Generate domain-specific wordlist using learned patterns"""
        if not self.patterns.get(domain):
            return base_words[:5000]  # Conservative default
            
        generated = set()
        high_priority = set()
        
        # Add pattern-based words
        for pattern in self.patterns[domain]:
            if pattern['confidence'] >= 80:
                generated.update(self._generate_variations(pattern))
                if pattern['examples']:
                    high_priority.update(pattern['examples'])
        
        # Add common services with domain context
        words = domain.split('.')
        company = words[0] if len(words) > 2 else domain.split('.')[0]
        
        for service_type, variants in self.common_services.items():
            for variant in variants:
                # Basic combinations
                generated.add(f"{variant}-{company}")
                generated.add(f"{company}-{variant}")
                generated.add(f"{variant}.{company}")
                generated.add(variant)
                
                # Environment-specific
                if service_type == 'dev':
                    generated.add(f"{variant}.internal")
                    generated.add(f"{variant}-internal")
                
                # Region-specific
                if service_type == 'geo':
                    generated.add(f"{company}-{variant}")
                    generated.add(f"{variant}.{company}")
        
        # Merge with base words, prioritizing learned patterns
        final_words = list(high_priority)
        final_words.extend(generated - set(final_words))
        final_words.extend([w for w in base_words if w not in final_words])
        
        # Return size based on AI mode
        if args.ai_mode == "aggressive":
            return final_words[:30000]
        elif args.ai_mode == "deep":
            return final_words[:20000]
        else:
            return final_words[:10000]
    
    def _generate_variations(self, pattern):
        """Generate variations based on a learned pattern"""
        variations = set()
        
        if not pattern.get('pattern'):
            return variations
            
        base = pattern['pattern']
        category = pattern.get('category', '')
        
        # Add basic pattern
        variations.add(base)
        
        # Generate environment variations
        if category == 'env':
            envs = ['dev', 'staging', 'uat', 'qa', 'prod', 'production']
            for env in envs:
                variations.add(f"{env}-{base}")
                variations.add(f"{base}-{env}")
        
        # Generate service variations
        elif category == 'service':
            regions = ['us', 'eu', 'asia', 'global']
            for region in regions:
                variations.add(f"{base}-{region}")
                variations.add(f"{region}-{base}")
        
        return variations

# ---------------------------
# ENHANCED AI SYSTEM
# ---------------------------
# ---------------------------
# ADVANCED AI SUBDOMAIN ANALYSIS
# ---------------------------
class AISubdomainAnalyzer:
    def __init__(self):
        self.patterns = {}
        self.discovered = set()
        self.industry_patterns = {}
        self.common_services = {
            'api': ['api', 'apis', 'rest', 'gw', 'gateway'],
            'dev': ['dev', 'development', 'staging', 'test', 'uat', 'qa'],
            'admin': ['admin', 'administrator', 'manage', 'manager', 'portal'],
            'cdn': ['cdn', 'static', 'assets', 'media', 'content'],
            'auth': ['auth', 'login', 'sso', 'identity', 'accounts'],
            'geo': ['us', 'eu', 'asia', 'in', 'uk', 'au']
        }
        self.max_patterns = 1000  # Prevent memory issues
        self.pattern_lock = threading.Lock()
    
    def learn_patterns(self, domain, known_subdomains):
        """Learn patterns from known subdomains using AI"""
        if not ai_system.ollama_available:
            return
        
        # Limit subdomains to analyze
        sample_size = min(50, len(known_subdomains))
        subdomain_sample = sample(list(known_subdomains), sample_size)
        
        prompt = f"""
        Analyze these subdomains for {domain}:
        {subdomain_sample}
        
        Identify:
        1. Common naming patterns (format: TYPE: pattern)
        2. Environment indicators (dev, staging, prod)
        3. Service patterns (api, cdn, mail)
        4. Geographic patterns (us, eu, asia)
        5. Department patterns (sales, marketing)
        
        Return only patterns, one per line:
        PATTERN: <pattern>
        CONFIDENCE: <0-100>
        CATEGORY: <env|service|geo|dept>
        EXAMPLES: <matching examples>
        """
        
        response = ai_system.query_ollama(prompt)
        if response:
            with self.pattern_lock:
                self.patterns[domain] = self._parse_patterns(response)
    
    def _parse_patterns(self, response):
        """Parse AI response into structured patterns"""
        patterns = []
        current = {}
        
        for line in response.splitlines():
            line = line.strip()
            if not line:
                if current:
                    patterns.append(current)
                    current = {}
                continue
                
            if line.startswith('PATTERN:'):
                current['pattern'] = line.split(':', 1)[1].strip()
            elif line.startswith('CONFIDENCE:'):
                try:
                    current['confidence'] = int(line.split(':', 1)[1].strip())
                except:
                    current['confidence'] = 50
            elif line.startswith('CATEGORY:'):
                current['category'] = line.split(':', 1)[1].strip().lower()
            elif line.startswith('EXAMPLES:'):
                current['examples'] = [x.strip() for x in line.split(':', 1)[1].strip().split(',')]
        
        if current:
            patterns.append(current)
        
        # Limit patterns to prevent memory issues
        return patterns[:self.max_patterns]
    
    def generate_targeted_wordlist(self, domain, base_words):
        """Generate domain-specific wordlist using learned patterns"""
        if not self.patterns.get(domain):
            return base_words[:5000]  # Conservative default
            
        generated = set()
        high_priority = set()
        
        # Add pattern-based words
        for pattern in self.patterns[domain]:
            if pattern['confidence'] >= 80:
                variations = self._generate_variations(pattern)
                generated.update(variations)
                if pattern['examples']:
                    high_priority.update(pattern['examples'])
        
        # Add common services with domain context
        words = domain.split('.')
        company = words[0] if len(words) > 2 else domain.split('.')[0]
        
        for service_type, variants in self.common_services.items():
            for variant in variants:
                # Basic combinations
                generated.add(f"{variant}-{company}")
                generated.add(f"{company}-{variant}")
                generated.add(f"{variant}.{company}")
                generated.add(variant)
                
                # Environment-specific
                if service_type == 'dev':
                    generated.add(f"{variant}.internal")
                    generated.add(f"{variant}-internal")
                
                # Region-specific
                if service_type == 'geo':
                    generated.add(f"{company}-{variant}")
                    generated.add(f"{variant}.{company}")
        
        # Merge with base words, prioritizing learned patterns
        final_words = list(high_priority)
        final_words.extend(generated - set(final_words))
        final_words.extend([w for w in base_words if w not in final_words])
        
        # Return size based on AI mode
        if args.ai_mode == "aggressive":
            return final_words[:30000]
        elif args.ai_mode == "deep":
            return final_words[:20000]
        else:
            return final_words[:10000]
    
    def _generate_variations(self, pattern):
        """Generate variations based on a learned pattern"""
        variations = set()
        
        if not pattern.get('pattern'):
            return variations
            
        base = pattern['pattern']
        category = pattern.get('category', '')
        
        # Add basic pattern
        variations.add(base)
        
        # Generate environment variations
        if category == 'env':
            envs = ['dev', 'staging', 'uat', 'qa', 'prod', 'production']
            for env in envs:
                variations.add(f"{env}-{base}")
                variations.add(f"{base}-{env}")
        
        # Generate service variations
        elif category == 'service':
            regions = ['us', 'eu', 'asia', 'global']
            for region in regions:
                variations.add(f"{base}-{region}")
                variations.add(f"{region}-{base}")
        
        return variations


class AIPenetrationSystem:
    def __init__(self):
        self.ai_ready = False
        self.model_type = "heuristic"
        self.ollama_available = False
        self.ollama_models = []
        self.subdomain_analyzer = AISubdomainAnalyzer()
        
    def setup_ai(self):
        """Setup AI system with real Ollama integration"""
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Initializing AI Engine...")
        
        # Check for Ollama
        if self._check_ollama():
            print(f"{Fore.GREEN}[AI]{Style.RESET_ALL} Ollama detected - Full AI capabilities enabled")
            self.ai_ready = True
            self.model_type = "ollama"
            self.ollama_available = True
            self._load_ollama_models()
            
            # Verify AI is working
            if self._verify_ai_working():
                print(f"{Fore.GREEN}[AI]{Style.RESET_ALL} AI system verified and ready!")
            else:
                print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} AI system available but verification failed")
            
            return True
            
        # Fallback to heuristic AI
        print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} Using Advanced Heuristic AI")
        self.ai_ready = True
        self.model_type = "heuristic_advanced"
        return True

    def _check_ollama(self):
        """Check if Ollama is available and has models"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                models = data.get('models', [])
                if models:
                    self.ollama_models = [model['name'] for model in models]
                    print(f"{Fore.GREEN}[AI]{Style.RESET_ALL} Models available: {', '.join(self.ollama_models)}")
                    return True
                else:
                    print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} Ollama running but no models downloaded")
            return False
        except:
            print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} Ollama not accessible")
            return False

    def _verify_ai_working(self):
        """Verify AI is actually working by making a test query"""
        try:
            test_prompt = "Hello, respond with just 'AI_READY' if you can read this."
            response = self.query_ollama(test_prompt)
            if response and "AI_READY" in response:
                return True
        except:
            pass
        return False

    def _load_ollama_models(self):
        """Get list of available Ollama models"""
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.ollama_models = [model['name'] for model in data.get('models', [])]
                if self.ollama_models:
                    print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Available models: {', '.join(self.ollama_models)}")
        except:
            self.ollama_models = []

    def query_ollama(self, prompt, model="llama2"):
        """Query Ollama with a prompt"""
        if not self.ollama_available:
            return None
            
        if not self.ollama_models:
            model = "llama2"
        else:
            model = self.ollama_models[0]
            
        try:
            data = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "top_k": 40
                }
            }
            response = requests.post("http://localhost:11434/api/generate", 
                                   json=data, timeout=60)
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                if args.verbose:
                    print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} Ollama API error: {response.status_code}")
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} Ollama query failed: {e}")
        return None

    def ai_smart_wordlist_selection(self, domain, base_words):
        """AI-powered smart wordlist selection with pattern learning"""
        # Initialize subdomain analyzer if needed
        if not hasattr(self, 'subdomain_analyzer'):
            self.subdomain_analyzer = AISubdomainAnalyzer()
        
        # If we have discovered subdomains, learn from them
        if discovered_subdomains:
            self.subdomain_analyzer.learn_patterns(domain, discovered_subdomains)
            
        # Generate smart wordlist
        if self.ollama_available and args.ai_recon:
            selected_words = self.subdomain_analyzer.generate_targeted_wordlist(domain, base_words)
            print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Generated {len(selected_words)} targeted subdomains")
            return selected_words
            
        # Fallback to basic selection
        if args.ai_mode == "aggressive":
            return base_words[:30000]  # Reduced from 50K to be more focused
        elif args.ai_mode == "deep":
            return base_words[:20000]  # Reduced from 35K to be more focused
        else:
            return base_words[:10000]  # Reduced from 25K to be more focused
        
        # REAL AI ANALYSIS - Enhanced domain analysis
        prompt = f"""
        Analyze the domain "{domain}" comprehensively and generate the MOST COMPREHENSIVE list of subdomain prefixes.
        Consider:
        - Common enterprise patterns (admin, api, app, dev, test, staging, prod)
        - Industry-specific terms (based on domain name patterns)
        - Geographic locations (us, eu, uk, in, au, etc.)
        - Environment names (development, testing, production, staging)
        - Service names (mail, ftp, cdn, static, assets, media)
        - Technology stacks (wp, wordpress, shop, store, blog)
        - Department names (hr, finance, sales, marketing, support)
        - Generate as many relevant subdomains as possible
        
        Domain: {domain}
        
        Return ONLY the subdomain prefixes, one per line, no explanations.
        Be extremely comprehensive and include all possible variations.
        """
        
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Performing deep domain analysis for {domain}...")
        ai_response = self.query_ollama(prompt)
        
        ai_selected = []
        if ai_response:
            for line in ai_response.split('\n'):
                line = line.strip()
                if line and not line.startswith(('```', '###', '---')) and len(line) < 50:
                    if line in base_words:
                        ai_selected.append(line)
                    else:
                        # Also add AI-suggested words even if not in base words
                        ai_selected.append(line)
            
            if ai_selected:
                print(f"{Fore.GREEN}[AI]{Style.RESET_ALL} AI generated {len(ai_selected)} subdomain candidates")
                
                # ENHANCED SUBDOMAIN TESTING - Based on AI mode
                if args.ai_mode == "aggressive":
                    target_count = 50000
                elif args.ai_mode == "deep":
                    target_count = 35000
                else:
                    target_count = 25000
                
                # Add more words to reach target count
                if len(ai_selected) < target_count:
                    additional_needed = target_count - len(ai_selected)
                    common_words = [w for w in base_words if w not in ai_selected]
                    ai_selected.extend(common_words[:additional_needed])
                
                print(f"{Fore.GREEN}[AI]{Style.RESET_ALL} Testing {len(ai_selected)} subdomains in {args.ai_mode} mode")
                return ai_selected[:target_count]
        
        # Enhanced Fallback - TEST EVEN MORE SUBDOMAINS
        print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} Using ultra-comprehensive selection for {domain}")
        if args.ai_mode == "aggressive":
            return base_words[:75000]  # 75K for aggressive
        elif args.ai_mode == "deep":
            return base_words[:50000]  # 50K for deep
        else:
            return base_words[:35000]  # 35K for smart

    def ai_recursive_subdomain_generation(self, base_domain, discovered_subs, current_level, max_levels):
        """AI-powered recursive subdomain generation"""
        if current_level >= max_levels:
            return []
        
        new_candidates = set()
        
        if self.ollama_available and args.ai_recon:
            prompt = f"""
            Based on these discovered subdomains for {base_domain}:
            {list(discovered_subs)[:20]}
            
            Generate new multi-level subdomain candidates for recursive discovery.
            Consider patterns like:
            - api.dev.subdomain.domain.com
            - admin.staging.subdomain.domain.com  
            - app.prod.service.domain.com
            - test.qa.internal.domain.com
            
            Return ONLY the full subdomain candidates, one per line.
            """
            
            ai_response = self.query_ollama(prompt)
            if ai_response:
                for line in ai_response.split('\n'):
                    line = line.strip()
                    if line and base_domain in line and len(line) < 100:
                        new_candidates.add(line)
        
        # Heuristic multi-level generation
        common_prefixes = ['api', 'admin', 'app', 'dev', 'test', 'staging', 'prod', 'internal', 'external']
        for sub in list(discovered_subs)[:100]:  # Limit to avoid explosion
            for prefix in common_prefixes:
                new_sub = f"{prefix}.{sub}"
                new_candidates.add(new_sub)
        
        return list(new_candidates)[:1000]  # Limit recursive candidates

# Initialize AI system
ai_system = AIPenetrationSystem()

# ---------------------------
# ENHANCED UTILITY FUNCTIONS
# ---------------------------
def normalize_subdomain(subdomain):
    """Normalize subdomain to avoid duplicates"""
    return subdomain.lower().strip().rstrip('.')

def add_subdomain(subdomain, source):
    """Add subdomain with duplicate checking"""
    normalized = normalize_subdomain(subdomain)
    with color_lock:
        if normalized not in discovered_subdomains:
            discovered_subdomains.add(normalized)
            print(f"{Fore.GREEN}[{source}]{Style.RESET_ALL} {normalized}")
            return True
    return False

def add_live_subdomain(subdomain, status_code, source):
    """Add live subdomain with status code"""
    normalized = normalize_subdomain(subdomain)
    with color_lock:
        if normalized not in live_subdomains:
            live_subdomains.add(normalized)
            status_color = Fore.GREEN if status_code == 200 else Fore.YELLOW if status_code in [301, 302] else Fore.BLUE
            status_text = "LIVE" if status_code == 200 else f"Status {status_code}"
            print(f"{Fore.GREEN}[{source}]{Style.RESET_ALL} {normalized} {status_color}[{status_text}]{Style.RESET_ALL}")
            return True
    return False

def add_live_url(url, status_code, source):
    """Add live URL with status code"""
    with color_lock:
        if url not in live_urls:
            live_urls.add(url)
            status_color = Fore.GREEN if status_code == 200 else Fore.YELLOW if status_code in [301, 302] else Fore.BLUE
            print(f"{Fore.BLUE}[{source}]{Style.RESET_ALL} {url} {status_color}[{status_code}]{Style.RESET_ALL}")
            return True
    return False

def dns_resolve_all(fqdn, timeout):
    """Resolve DNS for a domain"""
    ips, cnames = [], []
    if dns:
        try:
            r = dns.resolver.Resolver()
            r.lifetime = timeout
            try:
                answers = r.resolve(fqdn, "A")
                ips.extend(rr.to_text() for rr in answers)
            except: pass
            try:
                answers = r.resolve(fqdn, "AAAA")
                ips.extend(rr.to_text() for rr in answers)
            except: pass
            try:
                answers = r.resolve(fqdn, "CNAME")
                cnames.extend(str(rr.target).rstrip(".") for rr in answers)
            except: pass
            return (len(ips) > 0 or len(cnames) > 0), list(set(ips)), cnames
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[DNS]{Style.RESET_ALL} Failed to resolve {fqdn}: {e}")
            return False, [], []
    else:
        try:
            socket.setdefaulttimeout(timeout)
            infos = socket.getaddrinfo(fqdn, None)
            ips.extend(info[4][0] for info in infos if info and info[4])
            return (len(ips) > 0), list(set(ips)), []
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[DNS]{Style.RESET_ALL} Failed to resolve {fqdn}: {e}")
            return False, [], []

# ---------------------------
# ENHANCED HTTP PROBING
# ---------------------------
def http_probe_all(subdomains):
    """HTTP probe all subdomains to find live ones - ENHANCED"""
    print(f"{Fore.CYAN}[HTTP-PROBE]{Style.RESET_ALL} Probing {len(subdomains)} subdomains for live hosts...")
    
    live_hosts = set()
    
    def probe_subdomain(subdomain):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close"
        }
        
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{subdomain}/"
                r = requests.get(url, headers=headers, timeout=args.timeout, 
                               allow_redirects=True, verify=False)
                
                if r.status_code < 500:  # Consider any non-server-error as live
                    add_live_subdomain(subdomain, r.status_code, 'httpx')
                    add_live_url(url, r.status_code, 'httpx')
                    
                    # Also check common ports for this subdomain
                    if r.status_code == 200:
                        common_alt_ports = [8080, 8443, 3000, 5000, 8000]
                        for port in common_alt_ports:
                            alt_url = f"{scheme}://{subdomain}:{port}/"
                            try:
                                r_alt = requests.get(alt_url, headers=headers, timeout=2, 
                                                   allow_redirects=True, verify=False)
                                if r_alt.status_code < 500:
                                    add_live_url(alt_url, r_alt.status_code, 'alt-port')
                            except:
                                pass
                    
                    return subdomain
                    
            except requests.exceptions.SSLError:
                # Try HTTP if HTTPS fails
                continue
            except requests.exceptions.ConnectionError:
                # Connection failed, try next scheme
                continue
            except Exception as e:
                if args.verbose:
                    print(f"{Fore.YELLOW}[HTTP-PROBE]{Style.RESET_ALL} {subdomain} failed: {e}")
                continue
        
        return None
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(probe_subdomain, subdomain) for subdomain in subdomains]
        for future in as_completed(futures):
            result = future.result()
            if result:
                live_hosts.add(result)
    
    print(f"{Fore.GREEN}[HTTP-PROBE]{Style.RESET_ALL} Found {len(live_hosts)} live subdomains")
    return live_hosts

# ---------------------------
# WORDLIST HANDLING
# ---------------------------
def get_default_wordlist(wordlist_type="subdomains"):
    """Get default wordlist with proper fallback"""
    if wordlist_type == "subdomains":
        wordlist_dir = WORDLISTS_SUB
        default_files = ["2m-subdomains.txt", "subdomains.txt", "top1000.txt", "common.txt", "big.txt"]
    else:  # directories
        wordlist_dir = WORDLISTS_DIRS
        default_files = ["raft-large-directories.txt", "common.txt", "dirs.txt", "big.txt"]
    
    # Create wordlists directory if it doesn't exist
    if not os.path.exists(wordlist_dir):
        os.makedirs(wordlist_dir, exist_ok=True)
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Created wordlist directory: {wordlist_dir}")
    
    for filename in default_files:
        wordlist_path = os.path.join(wordlist_dir, filename)
        if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) > 0:
            file_size = os.path.getsize(wordlist_path)
            print(f"{Fore.GREEN}[WORDLIST]{Style.RESET_ALL} Using: {filename} ({file_size:,} bytes)")
            return wordlist_path
    
    # Create a basic wordlist if none exists
    basic_wordlist_path = os.path.join(wordlist_dir, "basic.txt")
    if wordlist_type == "subdomains":
        basic_words = ["www", "api", "app", "admin", "test", "dev", "staging", "mail", "ftp", "blog", 
                      "cdn", "mobile", "secure", "auth", "login", "dashboard", "portal", "backend", 
                      "frontend", "service", "gateway", "payment", "account", "user", "member"]
    else:
        basic_words = ["admin", "login", "dashboard", "api", "config", "backup", "test", "dev",
                      ".git", ".env", "robots.txt", "sitemap.xml", "phpinfo.php", "server-status"]
    
    with open(basic_wordlist_path, "w") as f:
        for word in basic_words:
            f.write(f"{word}\n")
    
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Created basic wordlist: {basic_wordlist_path}")
    return basic_wordlist_path

# ---------------------------
# PASSIVE RECONNAISSANCE FUNCTIONS (keep your existing ones)
# ---------------------------
def crtsh_query(domain):
    """Query crt.sh for subdomains"""
    s = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=args.timeout)
        if r.status_code == 200:
            for it in r.json():
                nm = it.get("name_value")
                if nm:
                    for line in nm.splitlines():
                        h = line.strip().lstrip("*.")
                        if h.endswith(domain): 
                            if add_subdomain(h, 'crt.sh'):
                                s.add(h)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} crt.sh failed: {e}")
    return s

def certspotter_query(domain):
    """Query Cert Spotter for subdomains"""
    s = set()
    try:
        r = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", 
                        timeout=args.timeout)
        if r.status_code == 200:
            for it in r.json():
                for name in it.get("dns_names", []):
                    h = name.strip().lstrip("*.")
                    if h.endswith(domain): 
                        if add_subdomain(h, 'certspotter'):
                            s.add(h)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} certspotter failed: {e}")
    return s

def wayback_cdx(domain):
    """Query Wayback Machine for subdomains"""
    s = set()
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        r = requests.get(url, timeout=args.timeout)
        if r.status_code == 200:
            arr = r.json()
            for rec in arr[1:]:
                try:
                    u = rec[0]
                    host = u.split("://", 1)[1].split("/", 1)[0]
                    if host.endswith(domain): 
                        if add_subdomain(host, 'wayback'):
                            s.add(host)
                except:
                    continue
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} wayback failed: {e}")
    return s

def bufferover_query(domain):
    """Query BufferOverflow for subdomains"""
    s = set()
    try:
        r = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=args.timeout)
        if r.status_code == 200:
            j = r.json()
            for key in ["FDNS_A", "RDNS"]:
                for entry in j.get(key, []) or []:
                    parts = entry.split(",")
                    if len(parts) > 1:
                        host = parts[1].strip()
                        if host.endswith(domain):
                            if add_subdomain(host, 'bufferover'):
                                s.add(host)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} bufferover failed: {e}")
    return s

def threatcrowd_query(domain):
    """Query ThreatCrowd for subdomains"""
    s = set()
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", 
                        timeout=args.timeout)
        if r.status_code == 200:
            j = r.json()
            for sub in j.get("subdomains", []):
                if sub.endswith(domain): 
                    if add_subdomain(sub, 'threatcrowd'):
                        s.add(sub)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} threatcrowd failed: {e}")
    return s

def hackertarget_query(domain):
    """Query HackerTarget for subdomains"""
    s = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=args.timeout)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if ',' in line:
                    host = line.split(',')[0].strip()
                    if host.endswith(domain):
                        if add_subdomain(host, 'hackertarget'):
                            s.add(host)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} hackertarget failed: {e}")
    return s

def subdomain_center_query(domain):
    """Query SubdomainCenter for subdomains"""
    s = set()
    try:
        r = requests.get(f"https://api.subdomain.center/?domain={domain}", timeout=args.timeout)
        if r.status_code == 200:
            j = r.json()
            for sub in j:
                if sub.endswith(domain):
                    if add_subdomain(sub, 'subdomain.center'):
                        s.add(sub)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} subdomain.center failed: {e}")
    return s

def anubis_query(domain):
    """Query Anubis for subdomains"""
    s = set()
    try:
        r = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=args.timeout)
        if r.status_code == 200:
            j = r.json()
            for sub in j:
                full_domain = f"{sub}.{domain}"
                if add_subdomain(full_domain, 'anubis'):
                    s.add(full_domain)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} anubis failed: {e}")
    return s

def subfinder_local(domain):
    """Use subfinder if available"""
    s = set()
    try:
        result = subprocess.run(["subfinder", "-version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"{Fore.CYAN}[SUBFINDER]{Style.RESET_ALL} Running subfinder...")
            cmd = ["subfinder", "-d", domain, "-silent", "-all"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    host = line.strip()
                    if host and host.endswith(domain):
                        if add_subdomain(host, 'subfinder'):
                            s.add(host)
                print(f"{Fore.GREEN}[SUBFINDER]{Style.RESET_ALL} Found {len(s)} subdomains")
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[SUBFINDER]{Style.RESET_ALL} Failed: {e}")
    return s

def amass_passive(domain):
    """Use Amass for passive enumeration"""
    s = set()
    try:
        result = subprocess.run(["amass", "-version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"{Fore.CYAN}[AMASS]{Style.RESET_ALL} Running amass passive...")
            cmd = ["amass", "enum", "-passive", "-d", domain, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    host = line.strip()
                    if host and host.endswith(domain):
                        if add_subdomain(host, 'amass'):
                            s.add(host)
                print(f"{Fore.GREEN}[AMASS]{Style.RESET_ALL} Found {len(s)} subdomains")
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[AMASS]{Style.RESET_ALL} Failed: {e}")
    return s

def assetfinder_local(domain):
    """Use assetfinder if available"""
    s = set()
    try:
        result = subprocess.run(["assetfinder", "-help"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"{Fore.CYAN}[ASSETFINDER]{Style.RESET_ALL} Running assetfinder...")
            cmd = ["assetfinder", "--subs-only", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    host = line.strip()
                    if host and host.endswith(domain):
                        if add_subdomain(host, 'assetfinder'):
                            s.add(host)
                print(f"{Fore.GREEN}[ASSETFINDER]{Style.RESET_ALL} Found {len(s)} subdomains")
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[ASSETFINDER]{Style.RESET_ALL} Failed: {e}")
    return s

def findomain_local(domain):
    """Use findomain if available"""
    s = set()
    try:
        result = subprocess.run(["findomain", "--help"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"{Fore.CYAN}[FINDOMAIN]{Style.RESET_ALL} Running findomain...")
            cmd = ["findomain", "-t", domain, "-q"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    host = line.strip()
                    if host and host.endswith(domain):
                        if add_subdomain(host, 'findomain'):
                            s.add(host)
                print(f"{Fore.GREEN}[FINDOMAIN]{Style.RESET_ALL} Found {len(s)} subdomains")
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[FINDOMAIN]{Style.RESET_ALL} Failed: {e}")
    return s

def passive_reconnaissance(domain):
    """Complete passive reconnaissance with ALL sources including tools"""
    print(f"{Fore.CYAN}[PHASE 1]{Style.RESET_ALL} Passive Reconnaissance")
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Gathering intelligence from 15+ sources and tools...")
    
    # Online API sources
    api_collectors = [
        crtsh_query,
        certspotter_query,
        wayback_cdx,
        bufferover_query,
        threatcrowd_query,
        hackertarget_query,
        subdomain_center_query,
        anubis_query
    ]
    
    # Local tool sources (if installed)
    tool_collectors = [
        subfinder_local,
        amass_passive,
        assetfinder_local,
        findomain_local
    ]
    
    all_subs = set()
    
    # Run API collectors in parallel
    print(f"{Fore.CYAN}[PASSIVE]{Style.RESET_ALL} Querying online sources...")
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(func, domain) for func in api_collectors]
        for future in as_completed(futures):
            try:
                results = future.result()
                all_subs.update(results)
            except Exception as e:
                if args.verbose:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} API collector failed: {e}")
    
    # Run tool collectors sequentially (tools handle their own parallelism)
    print(f"{Fore.CYAN}[PASSIVE]{Style.RESET_ALL} Running local tools...")
    for tool_func in tool_collectors:
        try:
            results = tool_func(domain)
            all_subs.update(results)
        except Exception as e:
            if args.verbose:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Tool {tool_func.__name__} failed: {e}")
    
    # Add common subdomains if none found
    if not all_subs:
        common_subs = [f"www.{domain}", f"api.{domain}", f"app.{domain}", f"admin.{domain}", 
                      f"mail.{domain}", f"blog.{domain}", f"dev.{domain}", f"test.{domain}",
                      f"staging.{domain}", f"cdn.{domain}", f"static.{domain}", f"assets.{domain}"]
        for sub in common_subs:
            if add_subdomain(sub, 'common'):
                all_subs.add(sub)
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Passive reconnaissance found {len(all_subs)} unique subdomains")
    
    # HTTP PROBE PASSIVE SUBDOMAINS
    if all_subs:
        live_subs = http_probe_all(all_subs)
        return live_subs
    
    return all_subs

# ---------------------------
# ENHANCED ACTIVE RECONNAISSANCE WITH RECURSIVE DISCOVERY
# ---------------------------
def active_reconnaissance(domain, passive_subs, current_level=1):
    """Enhanced active subdomain enumeration with recursive discovery"""
    print(f"{Fore.CYAN}[PHASE 2.{current_level}]{Style.RESET_ALL} Active Reconnaissance (Level {current_level})")
    
    # Load wordlist
    if args.wordlist:
        wordlist_path = args.wordlist
        if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) > 0:
            with open(wordlist_path, "r") as f:
                base_words = [line.strip() for line in f if line.strip()]
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Using custom wordlist: {wordlist_path} ({len(base_words)} entries)")
        else:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Custom wordlist not found or empty: {wordlist_path}")
            base_words = []
    else:
        wordlist_path = get_default_wordlist("subdomains")
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, "r") as f:
                base_words = [line.strip() for line in f if line.strip()]
        else:
            base_words = ["www", "api", "app", "admin", "test", "dev", "staging", "mail", "ftp", "blog"]
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Using built-in wordlist ({len(base_words)} entries)")
    
    # AI-powered smart selection - ENHANCED
    if ai_system.ai_ready and args.ai_recon:
        words = ai_system.ai_smart_wordlist_selection(domain, base_words)
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Testing {len(words)} subdomains with {args.ai_mode} AI mode")
    else:
        # No AI: Enhanced subdomain testing
        if args.ai_mode == "aggressive":
            words = base_words[:75000]  # 75K for aggressive
        elif args.ai_mode == "deep":
            words = base_words[:50000]  # 50K for deep
        else:
            words = base_words[:35000]  # 35K for smart
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Testing {len(words)} subdomains")
    
    found_subs = set()
    tested_count = 0
    
    def check_subdomain(subdomain):
        nonlocal tested_count
        tested_count += 1
        
        # Show progress every 1000 tests
        if tested_count % 1000 == 0:
            print(f"{Fore.CYAN}[PROGRESS]{Style.RESET_ALL} Tested {tested_count}/{len(words)} subdomains...")
        
        ok, ips, cnames = dns_resolve_all(subdomain, args.timeout)
        if ok:
            if add_subdomain(subdomain, f'active-L{current_level}'):
                if ips:
                    print(f"{Fore.BLUE}[DNS]{Style.RESET_ALL} {subdomain} -> {', '.join(ips[:2])}")
                else:
                    print(f"{Fore.BLUE}[DNS]{Style.RESET_ALL} {subdomain} -> CNAME: {cnames[0]}")
                return subdomain
        return None
    
    with ThreadPoolExecutor(max_workers=min(args.workers, 200)) as executor:
        futures = []
        for word in words:
            subdomain = f"{word}.{domain}"
            futures.append(executor.submit(check_subdomain, subdomain))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_subs.add(result)
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Level {current_level} found {len(found_subs)} new subdomains")
    
    # HTTP PROBE ACTIVE SUBDOMAINS
    live_subs = set()
    if found_subs:
        live_subs = http_probe_all(found_subs)
    
    # RECURSIVE DISCOVERY
    if current_level < args.levels and found_subs:
        print(f"{Fore.CYAN}[RECURSIVE]{Style.RESET_ALL} Starting recursive discovery (Level {current_level + 1})")
        
        # AI-powered recursive generation
        recursive_candidates = ai_system.ai_recursive_subdomain_generation(
            domain, found_subs, current_level, args.levels
        )
        
        if recursive_candidates:
            recursive_subs = set()
            with ThreadPoolExecutor(max_workers=min(args.workers, 100)) as executor:
                futures = [executor.submit(check_subdomain, candidate) for candidate in recursive_candidates]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        recursive_subs.add(result)
            
            if recursive_subs:
                print(f"{Fore.GREEN}[RECURSIVE]{Style.RESET_ALL} Found {len(recursive_subs)} recursive subdomains")
                found_subs.update(recursive_subs)
                
                # Probe recursive subdomains
                recursive_live = http_probe_all(recursive_subs)
                live_subs.update(recursive_live)
    
    return live_subs

# ---------------------------
# PORT SCANNING
# ---------------------------
def port_scan_host(host, ports):
    """Scan ports for a host"""
    open_ports = []
    
    def check_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect((host, port))
            s.close()
            return port
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(check_port, port) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"{Fore.BLUE}[PORT]{Style.RESET_ALL} {host}:{result} open")
    
    return open_ports

def port_scanning(subdomains):
    """Port scanning phase with AI-enhanced port selection"""
    print(f"{Fore.CYAN}[PHASE 3]{Style.RESET_ALL} Port Scanning")
    
    if args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    else:
        ports = COMMON_PORTS
        
    # AI-enhanced port selection
    if ai_system.ollama_available and args.ai_scan:
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Analyzing targets for service patterns...")
        for subdomain in subdomains:
            prompt = f"""
            Analyze this subdomain and predict potential services/ports:
            Subdomain: {subdomain}
            
            Consider:
            1. Common web services (HTTP/S, APIs)
            2. Database ports (MySQL, PostgreSQL, MongoDB)
            3. Development services (SSH, FTP)
            4. Application-specific ports
            5. Microservices architecture
            
            Return only port numbers, one per line.
            """
            ai_ports = ai_system.query_ollama(prompt)
            if ai_ports:
                for port in ai_ports.splitlines():
                    try:
                        port_num = int(port.strip())
                        if port_num > 0 and port_num < 65536:  # Valid port range
                            ports.append(port_num)
                    except:
                        continue
        ports = list(set(ports))  # Remove duplicates
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanning {len(subdomains)} hosts on {len(ports)} ports...")
    
    results = {}
    for subdomain in list(subdomains)[:20]:  # Limit to 20 hosts for performance
        print(f"{Fore.CYAN}[SCANNING]{Style.RESET_ALL} {subdomain}")
        open_ports = port_scan_host(subdomain, ports)
        if open_ports:
            results[subdomain] = open_ports
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Found open ports on {len(results)} hosts")
    return results

# ---------------------------
# ENHANCED DIRECTORY BRUTEFORCING
# ---------------------------
def directory_scan(url, wordlist):
    """Enhanced directory scanning for a URL"""
    found_paths = []
    
    if wordlist and os.path.exists(wordlist) and os.path.getsize(wordlist) > 0:
        with open(wordlist, "r") as f:
            wordlist_items = [line.strip() for line in f if line.strip()]
        print(f"{Fore.CYAN}[DIR]{Style.RESET_ALL} Using wordlist: {os.path.basename(wordlist)} ({len(wordlist_items)} entries)")
    else:
        # Enhanced built-in wordlist
        wordlist_items = [
            "admin", "administrator", "login", "dashboard", "api", "config", "backup", "test", "dev",
            ".git", ".env", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml", "sitemap.json", 
            "phpinfo.php", "server-status", "web.config", "wp-admin", "wp-login.php", "administrator",
            "phpmyadmin", "mysql", "db", "database", "backup", "backups", "old", "temp", "tmp",
            "upload", "uploads", "images", "img", "css", "js", "assets", "static", "media",
            "cgi-bin", "cgi", "bin", "scripts", "script", "web", "webapp", "app", "application",
            "portal", "control", "manager", "management", "adminpanel", "cp", "controlpanel",
            "secure", "security", "private", "hidden", "secret", "conf", "configs", "configuration"
        ]
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Using enhanced built-in directory wordlist ({len(wordlist_items)} entries)")
    
    # Enhanced file extensions
    extensions = ["", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".json", ".xml", ".txt", ".bak", ".old"]
    
    def check_path(path):
        try:
            full_url = f"{url}/{path}"
            r = requests.get(full_url, timeout=args.timeout, verify=False, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403, 401]:
                add_live_url(full_url, r.status_code, 'dir')
                return {"url": full_url, "status": r.status_code, "path": path}
        except:
            pass
        return None
    
    # Test paths with extensions
    test_paths = []
    for path in wordlist_items[:5000]:  # Increased to 5000 paths
        test_paths.append(path)
        for ext in extensions:
            test_paths.append(f"{path}{ext}")
    
    # Remove duplicates
    test_paths = list(set(test_paths))[:3000]  # Limit to 3000 total paths
    
    print(f"{Fore.CYAN}[DIR]{Style.RESET_ALL} Scanning {url} with {len(test_paths)} paths...")
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_path, path) for path in test_paths]
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_paths.append(result)
    
    return found_paths

def directory_scanning(urls):
    """Enhanced directory scanning phase with AI - SCAN ALL URLS"""
    print(f"{Fore.CYAN}[PHASE 4]{Style.RESET_ALL} Directory Scanning")
    
    if args.dir_wordlist:
        wordlist_path = args.dir_wordlist
    else:
        wordlist_path = get_default_wordlist("dirs")
    
    # AI-enhanced directory prediction
    if ai_system.ollama_available and args.ai_scan:
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Analyzing target for custom directory patterns...")
        for url in urls:
            prompt = f"""
            Analyze this URL and predict potential high-value directories:
            URL: {url}
            
            Consider:
            1. Common web frameworks and their directory structures
            2. Development environments (dev, staging, test)
            3. Application-specific paths
            4. Admin interfaces and dashboards
            5. API endpoints and documentation
            6. Backup and configuration files
            
            Return only paths, one per line.
            """
            ai_paths = ai_system.query_ollama(prompt)
            if ai_paths:
                with open(wordlist_path, 'a') as f:
                    for path in ai_paths.splitlines():
                        if path.strip() and len(path.strip()) < 50:  # Sanity check
                            f.write(f"{path.strip()}\n")
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanning {len(urls)} URLs for directories...")
    
    results = {}
    # SCAN ALL URLS, not just first 5
    for url in list(urls):
        print(f"{Fore.CYAN}[DIR]{Style.RESET_ALL} Scanning: {url}")
        paths = directory_scan(url, wordlist_path)
        if paths:
            results[url] = paths
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Found directories on {len(results)} URLs")
    return results

# ---------------------------
# ENHANCED CRAWLING
# ---------------------------
def crawl_website(url, max_pages=100):
    """Enhanced website crawling with better URL handling and rate limiting"""
    print(f"{Fore.CYAN}[CRAWL]{Style.RESET_ALL} Crawling {url} (max {max_pages} pages)")
    
    # Normalize the base URL
    try:
        base_url = url
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
        base_parsed = urlparse(base_url)
        base_domain = base_parsed.netloc

        # Test initial connection with fallback
        try:
            response = requests.get(base_url, timeout=args.timeout, verify=False, 
                                 allow_redirects=True)
            if response.status_code in [301, 302, 307, 308]:  # Follow redirects
                base_url = response.url
                base_parsed = urlparse(base_url)
                base_domain = base_parsed.netloc
            print(f"{Fore.GREEN}[CRAWL]{Style.RESET_ALL} Initial connection successful: {response.status_code}")
            add_live_url(base_url, response.status_code, 'crawl')
        except requests.RequestException as e:
            # Try HTTP if HTTPS fails
            if base_url.startswith('https://'):
                base_url = 'http://' + base_url[8:]
                try:
                    response = requests.get(base_url, timeout=args.timeout, verify=False)
                    print(f"{Fore.GREEN}[CRAWL]{Style.RESET_ALL} HTTP connection successful: {response.status_code}")
                    add_live_url(base_url, response.status_code, 'crawl')
                except requests.RequestException as e:
                    print(f"{Fore.RED}[CRAWL]{Style.RESET_ALL} All connection attempts failed: {e}")
                    return []

        crawled_urls = set()
        to_crawl = [base_url]
        seen_urls = {base_url}  # Track URLs we've seen to avoid duplicates
        error_counts = {}  # Track error counts per domain for rate limiting

        def normalize_url(url, base):
            """Normalize URL for consistent comparison"""
            try:
                # Handle relative URLs
                if not url.startswith(('http://', 'https://')):
                    url = urljoin(base, url)
                
                # Parse and normalize
                parsed = urlparse(url)
                
                # Remove default ports and fragments
                netloc = parsed.netloc
                if parsed.scheme == 'http' and ':80' in netloc:
                    netloc = netloc.replace(':80', '')
                elif parsed.scheme == 'https' and ':443' in netloc:
                    netloc = netloc.replace(':443', '')
                
                # Reconstruct URL without fragments and normalize slashes
                path = parsed.path
                if not path:
                    path = '/'
                elif path != '/':
                    path = path.rstrip('/')
                
                # Handle query parameters
                query = parsed.query
                if query:
                    # Sort query parameters for consistency
                    params = parse_qs(query)
                    query = '&'.join(f"{k}={v[0]}" for k, v in sorted(params.items()))
                
                normalized = f"{parsed.scheme}://{netloc}{path}"
                if query:
                    normalized += f"?{query}"
                return normalized
            except Exception:
                return url

        def extract_links(html, current_url):
            """Extract links with improved normalization and filtering"""
            links = set()
            try:
                soup = BeautifulSoup(html, 'html.parser')
                base_tag = soup.find('base', href=True)
                base_href = base_tag['href'] if base_tag else current_url

                # Helper to process extracted URLs
                def process_url(url_str):
                    try:
                        full_url = normalize_url(url_str.strip(), base_href)
                        parsed = urlparse(full_url)
                        # Only include URLs on same domain/subdomain
                        if parsed.netloc.endswith(base_domain):
                            # Skip common non-content URLs and file types
                            skip_patterns = [
                                '.png', '.jpg', '.gif', '.css', '.js', '.ico', '.svg', 
                                '.woff', '.ttf', '.pdf', '.zip', '.tar', '.gz'
                            ]
                            if not any(pat in parsed.path.lower() for pat in skip_patterns):
                                links.add(full_url)
                    except Exception:
                        pass

                # Extract URLs from different tags
                for tag_type, attr in [
                    ('a', 'href'), ('link', 'href'), ('img', 'src'),
                    ('script', 'src'), ('form', 'action'), ('iframe', 'src')
                ]:
                    for tag in soup.find_all(tag_type, {attr: True}):
                        url_str = tag[attr]
                        if url_str and not url_str.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                            process_url(url_str)

            except Exception as e:
                if args.verbose:
                    print(f"{Fore.YELLOW}[CRAWL]{Style.RESET_ALL} Link extraction error: {e}")
            return links

        # Enhanced headers with encoding support
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close"
        }

        # Rate limiting parameters
        rate_limit_delay = 1.0  # Base delay between requests
        max_retries = 3
        retry_delay = 2.0

        while to_crawl and len(crawled_urls) < max_pages:
            current_url = to_crawl.pop(0)
            current_domain = urlparse(current_url).netloc

            # Skip if already crawled
            if current_url in crawled_urls:
                continue

            # Rate limiting based on errors
            if error_counts.get(current_domain, 0) > max_retries:
                time.sleep(retry_delay)
                error_counts[current_domain] = 0

            try:
                response = requests.get(
                    current_url, 
                    headers=headers, 
                    timeout=args.timeout, 
                    verify=False,
                    allow_redirects=True
                )
                # Process the response
                crawled_urls.add(current_url)
                add_live_url(current_url, response.status_code, 'crawl')

                # Extract links if it's HTML content
                if 'text/html' in response.headers.get('content-type', '').lower():
                    new_links = extract_links(response.text, current_url)
                    for link in new_links:
                        if link not in seen_urls:
                            seen_urls.add(link)
                            to_crawl.append(link)

                # Successful request, reset error count
                error_counts[current_domain] = 0
                time.sleep(rate_limit_delay)  # Basic rate limiting

            except requests.exceptions.RequestException as e:
                if args.verbose:
                    print(f"{Fore.YELLOW}[CRAWL]{Style.RESET_ALL} Failed to crawl {current_url}: {e}")
                # Increment error count for this domain
                error_counts[current_domain] = error_counts.get(current_domain, 0) + 1

            except Exception as e:
                if args.verbose:
                    print(f"{Fore.YELLOW}[CRAWL]{Style.RESET_ALL} Unexpected error: {e}")
                continue

            # Progress update every 10 URLs
            if len(crawled_urls) % 10 == 0:
                print(f"{Fore.CYAN}[CRAWL]{Style.RESET_ALL} Progress: {len(crawled_urls)} URLs crawled, {len(to_crawl)} remaining")

        print(f"{Fore.GREEN}[CRAWL]{Style.RESET_ALL} Crawled {len(crawled_urls)} pages from {url}")
        return list(crawled_urls)

    except Exception as e:
        print(f"{Fore.RED}[CRAWL]{Style.RESET_ALL} Fatal crawling error: {e}")
        return []

async def analyze_javascript(urls, js_recon):
    """Analyze JavaScript files for endpoints and sensitive information"""
    print(f"{Fore.CYAN}[JS-RECON]{Style.RESET_ALL} Analyzing JavaScript files...")
    
    import aiohttp
    from urllib.parse import urljoin
    
    async with aiohttp.ClientSession() as session:
        for url in urls:
            try:
                # First analyze the main page
                await js_recon.analyze_js(url, session)
                
                # Get all discovered JS files
                js_files = js_recon.js_files
                print(f"{Fore.CYAN}[JS-RECON]{Style.RESET_ALL} Found {len(js_files)} JavaScript files in {url}")
                
                # Analyze each JS file
                for js_url in js_files:
                    if not js_url.startswith(('http://', 'https://')):
                        js_url = urljoin(url, js_url)
                    await js_recon.analyze_js(js_url, session)
                
                # Report findings
                if js_recon.discovered_endpoints:
                    print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Discovered {len(js_recon.discovered_endpoints)} endpoints")
                    for endpoint in js_recon.discovered_endpoints:
                        print(f"{Fore.BLUE}[JS-ENDPOINT]{Style.RESET_ALL} {endpoint}")
                
                if js_recon.api_patterns:
                    print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Detected {len(js_recon.api_patterns)} API patterns")
                    for pattern in js_recon.api_patterns:
                        print(f"{Fore.BLUE}[JS-API]{Style.RESET_ALL} {pattern}")
                
                if js_recon.secrets:
                    print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Found {len(js_recon.secrets)} potential secrets")
                    for secret in js_recon.secrets:
                        print(f"{Fore.RED}[JS-SECRET]{Style.RESET_ALL} {secret}")
                
            except Exception as e:
                if args.verbose:
                    print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Error analyzing {url}: {e}")

def website_crawling(urls):
    """Enhanced website crawling phase with AI path prediction and JS analysis"""
    print(f"{Fore.CYAN}[PHASE 4.5]{Style.RESET_ALL} Website Crawling")
    
    # Handle single URL input
    if isinstance(urls, str):
        urls = [urls]
    elif not urls:
        urls = []
        if args.url:
            urls.append(args.url)
    
    if not urls:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No URLs found for crawling")
        return {}
        
    results = {}
    for url in urls:
        print(f"{Fore.CYAN}[CRAWL]{Style.RESET_ALL} Starting crawl for {url}")
        crawled = crawl_website(url)
        if crawled:
            results[url] = crawled
            print(f"{Fore.GREEN}[CRAWL]{Style.RESET_ALL} Found {len(crawled)} URLs for {url}")
    
    return results
    
    if not urls:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No URLs found for crawling")
        return {}
        
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Crawling {len(urls)} URLs...")
    
    # AI-enhanced crawling patterns
    if ai_system.ollama_available and args.ai_scan:
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Analyzing websites for intelligent crawling...")
        for url in urls:
            prompt = f"""
            Analyze this website URL for potential valuable paths:
            URL: {url}
            
            Consider:
            1. Common web application structures
            2. Content management systems
            3. API documentation paths
            4. Authentication endpoints
            5. Admin interfaces
            6. Development resources
            7. JavaScript and asset locations
            
            Return only paths, one per line.
            """
            ai_paths = ai_system.query_ollama(prompt)
            if ai_paths:
                for path in ai_paths.splitlines():
                    path = path.strip()
                    if path and len(path) < 100:  # Sanity check
                        full_url = urljoin(url, path)
                        discovered_urls.add(full_url)
    
    results = {}
    # CRAWL ALL URLS, not just first 3
    for url in list(urls):
        print(f"{Fore.CYAN}[CRAWL]{Style.RESET_ALL} Starting crawl: {url}")
        crawled_urls = crawl_website(url)
        if crawled_urls:
            results[url] = crawled_urls
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Crawled {len(results)} URLs")
    
    # Initialize and run JavaScript reconnaissance
    if BeautifulSoup:  # Only if bs4 is available
        js_recon = JSRecon()
        print(f"{Fore.CYAN}[JS-RECON]{Style.RESET_ALL} Starting JavaScript analysis...")
        
        # Create event loop for async operation
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        # Run JavaScript analysis
        try:
            loop.run_until_complete(analyze_javascript(urls, js_recon))
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} JavaScript analysis failed: {e}")
    else:
        if args.verbose:
            print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} BeautifulSoup not available, skipping JavaScript analysis")
    
    return results

# ---------------------------
# JAVASCRIPT RECONNAISSANCE
# ---------------------------
class JSRecon:
    def __init__(self):
        self.discovered_endpoints = set()
        self.js_files = set()
        self.api_patterns = set()
        self.secrets = set()
    
    async def analyze_js(self, url, session):
        """Analyze JavaScript files for endpoints and secrets"""
        try:
            async with session.get(url) as response:
                if 'javascript' in response.headers.get('content-type', ''):
                    content = await response.text()
                    
                    # Basic endpoint extraction
                    self._extract_endpoints(content, url)
                    
                    # Find JS imports
                    self._find_imports(content, url)
                    
                    # AI-powered analysis
                    if ai_system.ollama_available:
                        await self._ai_analyze_js(url, content)
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS]{Style.RESET_ALL} Failed to analyze {url}: {e}")
    
    def _extract_endpoints(self, content, source_url):
        """Extract endpoints from JavaScript content"""
        # URLs and endpoints
        urls = re.findall(r'(?:"|\'|\`)(?:https?:)?//[^\s\'"`,]+', content)
        self.discovered_endpoints.update(urls)
        
        # API endpoints
        apis = re.findall(r'(?:"|\'|\`)/?api/v?\d*/[^\s\'"`,]+', content)
        self.discovered_endpoints.update(apis)
        
        # GraphQL endpoints
        graphql = re.findall(r'(?:"|\'|\`)/(?:graphql|graphiql|gql)[^\s\'"`,]*', content)
        self.discovered_endpoints.update(graphql)
        
        # WebSocket endpoints
        ws = re.findall(r'(?:"|\'|\`)(?:ws|wss)://[^\s\'"`,]+', content)
        self.discovered_endpoints.update(ws)
    
    def _find_imports(self, content, url):
        """Find JavaScript imports and modules"""
        # ES6 imports
        imports = re.findall(r'import.*?from\s+[\'"`](.*?)[\'"`]', content)
        
        # Script tags
        scripts = re.findall(r'src=[\'"`](.*?\.js)[\'"`]', content)
        
        # Resolve and add JS files
        for js in imports + scripts:
            if js.startswith(('http://', 'https://')):
                self.js_files.add(js)
            else:
                self.js_files.add(urljoin(url, js))
    
    async def _ai_analyze_js(self, url, content):
        """AI-powered JavaScript analysis"""
        prompt = f"""
        Analyze this JavaScript code for security-relevant items:
        1. API endpoints and patterns
        2. Authentication endpoints
        3. Hidden features
        4. AWS/Cloud URLs
        5. Sensitive variables
        6. WebSocket endpoints
        
        JavaScript from: {url}
        Content: {content[:2000]}
        
        Return findings one per line:
        ENDPOINT: <url>
        AUTH: <auth_endpoint>
        API: <api_endpoint>
        CLOUD: <cloud_url>
        WS: <websocket_url>
        SECRET: <variable_name>
        """
        
        findings = ai_system.query_ollama(prompt)
        if findings:
            self._parse_ai_findings(findings)
    
    def _parse_ai_findings(self, findings):
        """Parse AI analysis results"""
        for line in findings.splitlines():
            if not line.strip():
                continue
            
            try:
                category, value = line.split(':', 1)
                value = value.strip()
                
                if category == 'ENDPOINT':
                    self.discovered_endpoints.add(value)
                elif category == 'AUTH':
                    self.discovered_endpoints.add(value)
                elif category == 'API':
                    self.api_patterns.add(value)
                elif category == 'CLOUD':
                    self.discovered_endpoints.add(value)
                elif category == 'WS':
                    self.discovered_endpoints.add(value)
                elif category == 'SECRET':
                    self.secrets.add(value)
            except:
                continue
class JSRecon:
    def __init__(self):
        self.discovered_endpoints = set()
        self.js_files = set()
        self.api_patterns = set()
        self.secrets = set()
    
    async def analyze_js(self, url, session):
        """Analyze JavaScript files for endpoints and secrets"""
        try:
            async with session.get(url) as response:
                if 'javascript' in response.headers.get('content-type', ''):
                    content = await response.text()
                    
                    # Basic endpoint extraction
                    self._extract_endpoints(content, url)
                    
                    # Find JS imports
                    self._find_imports(content, url)
                    
                    # AI-powered analysis
                    if ai_system.ollama_available:
                        await self._ai_analyze_js(url, content)
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS]{Style.RESET_ALL} Failed to analyze {url}: {e}")
    
    def _extract_endpoints(self, content, source_url):
        """Extract endpoints from JavaScript content"""
        # URLs and endpoints
        urls = re.findall(r'(?:"|\'|\`)(?:https?:)?//[^\s\'"`,]+', content)
        self.discovered_endpoints.update(urls)
        
        # API endpoints
        apis = re.findall(r'(?:"|\'|\`)/?api/v?\d*/[^\s\'"`,]+', content)
        self.discovered_endpoints.update(apis)
        
        # GraphQL endpoints
        graphql = re.findall(r'(?:"|\'|\`)/(?:graphql|graphiql|gql)[^\s\'"`,]*', content)
        self.discovered_endpoints.update(graphql)
        
        # WebSocket endpoints
        ws = re.findall(r'(?:"|\'|\`)(?:ws|wss)://[^\s\'"`,]+', content)
        self.discovered_endpoints.update(ws)
    
    def _find_imports(self, content, base_url):
        """Find JavaScript imports and modules"""
        # ES6 imports
        imports = re.findall(r'import.*?from\s+[\'"`](.*?)[\'"`]', content)
        
        # Script tags
        scripts = re.findall(r'src=[\'"`](.*?\.js)[\'"`]', content)
        
        # Resolve and add JS files
        for js in imports + scripts:
            if js.startswith(('http://', 'https://')):
                self.js_files.add(js)
            else:
                self.js_files.add(urljoin(base_url, js))
    
    async def _ai_analyze_js(self, url, content):
        """AI-powered JavaScript analysis"""
        prompt = f"""
        Analyze this JavaScript code for security-relevant items:
        1. API endpoints and patterns
        2. Authentication endpoints
        3. Hidden features
        4. AWS/Cloud URLs
        5. Sensitive variables
        6. WebSocket endpoints
        
        JavaScript from: {url}
        Content: {content[:2000]}
        
        Return findings one per line:
        ENDPOINT: <url>
        AUTH: <auth_endpoint>
        API: <api_endpoint>
        CLOUD: <cloud_url>
        WS: <websocket_url>
        SECRET: <variable_name>
        """
        
        findings = ai_system.query_ollama(prompt)
        if findings:
            self._parse_ai_findings(findings)
    
    def _parse_ai_findings(self, findings):
        """Parse AI analysis results"""
        for line in findings.splitlines():
            if not line.strip():
                continue
            
            try:
                category, value = line.split(':', 1)
                value = value.strip()
                
                if category == 'ENDPOINT':
                    self.discovered_endpoints.add(value)
                elif category == 'AUTH':
                    self.discovered_endpoints.add(value)
                elif category == 'API':
                    self.api_patterns.add(value)
                elif category == 'CLOUD':
                    self.discovered_endpoints.add(value)
                elif category == 'WS':
                    self.discovered_endpoints.add(value)
                elif category == 'SECRET':
                    self.secrets.add(value)
            except:
                continue

# ---------------------------
# TECHNOLOGY STACK DETECTION
# ---------------------------
def detect_technology(url):
    """Enhanced technology stack detection with cloud and framework focus"""
    tech_stack = {
        "cms": [],
        "frameworks": [],
        "programming_languages": [],
        "web_servers": [],
        "databases": [],
        "javascript_libraries": [],
        "analytics": [],
        "caching": [],
        "cdn": [],
        "cloud_services": [],
        "security_tools": [],
        "operating_systems": []
    }
    
    # Enhanced patterns
    cloud_patterns = {
        "aws": [
            "amazonaws.com", "aws.amazon", "cloudfront.net", "s3.amazonaws",
            "elasticbeanstalk", "elb.amazonaws", "aws-lambda"
        ],
        "gcp": [
            "googleapis.com", "googleusercontent", "cloud.google", 
            "appspot.com", "cloudfunctions.net"
        ],
        "azure": [
            "azure.com", "azurewebsites.net", "cloudapp.net", 
            "azure-api.net", "azureedge.net"
        ],
        "cloudflare": ["cloudflare", "cloudflare-cdn", "workers.dev"],
        "digitalocean": ["digitaloceanspaces", "digitalocean.com"],
        "heroku": ["herokuapp.com", "heroku.com"]
    }
    
    security_patterns = {
        "waf": ["cloudflare-waf", "awswaf", "modsecurity"],
        "cdn": ["cloudfront", "akamai", "fastly", "cloudflare"],
        "auth": ["auth0.com", "okta.com", "onelogin"],
        "certificates": ["digicert", "letsencrypt", "sectigo"]
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=args.timeout, verify=False)
        content = response.text.lower()
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        # CMS Detection
        cms_indicators = {
            "wordpress": ["wp-content", "wp-includes", "wordpress", "/wp-json/"],
            "joomla": ["joomla", "media/jui/", "templates/ja_purity/"],
            "drupal": ["drupal", "sites/all/", "misc/drupal.js"],
            "magento": ["magento", "static/version"],
            "shopify": ["shopify"],
            "prestashop": ["prestashop"],
            "wix": ["wix.com", "static.parastorage.com"],
            "squarespace": ["squarespace"],
            "ghost": ["ghost", "assets/built/"],
            "typo3": ["typo3", "typo3conf/"]
        }
        
        for cms, indicators in cms_indicators.items():
            if any(indicator in content for indicator in indicators):
                tech_stack["cms"].append(cms)
        
        # Framework Detection
        framework_indicators = {
            "laravel": ["laravel", "csrf-token"],
            "django": ["django", "csrfmiddleware"],
            "rails": ["rails", "ruby on rails"],
            "express": ["express", "x-powered-by: express"],
            "spring": ["spring", "spring framework"],
            "asp.net": ["asp.net", "x-aspnet-version"],
            "flask": ["flask"],
            "react": ["react", "reactjs", "__react"],
            "angular": ["angular", "ng-", "angularjs"],
            "vue": ["vue", "vue.js", "__vue__"]
        }
        
        for framework, indicators in framework_indicators.items():
            if any(indicator in content for indicator in indicators) or \
               any(indicator in str(headers_lower) for indicator in indicators):
                tech_stack["frameworks"].append(framework)
        
        # Server Detection
        server_headers = headers_lower.get('server', '')
        if 'apache' in server_headers:
            tech_stack["web_servers"].append("Apache")
        if 'nginx' in server_headers:
            tech_stack["web_servers"].append("Nginx")
        if 'iis' in server_headers.lower():
            tech_stack["web_servers"].append("IIS")
        if 'cloudflare' in server_headers.lower():
            tech_stack["cdn"].append("Cloudflare")
        
        # Programming Languages
        if 'php' in server_headers or '.php' in content:
            tech_stack["programming_languages"].append("PHP")
        if 'python' in server_headers or 'django' in tech_stack["frameworks"]:
            tech_stack["programming_languages"].append("Python")
        if 'ruby' in server_headers or 'rails' in tech_stack["frameworks"]:
            tech_stack["programming_languages"].append("Ruby")
        if 'asp.net' in tech_stack["frameworks"]:
            tech_stack["programming_languages"].append("C#")
        if 'node.js' in server_headers or 'express' in tech_stack["frameworks"]:
            tech_stack["programming_languages"].append("JavaScript (Node.js)")
        
        # JavaScript Libraries
        js_libraries = {
            "jquery": ["jquery", "jquery.min.js"],
            "bootstrap": ["bootstrap", "bootstrap.min.js"],
            "modernizr": ["modernizr"],
            "moment.js": ["moment.min.js"],
            "chart.js": ["chart.js", "chart.min.js"],
            "d3.js": ["d3.js", "d3.min.js"],
            "three.js": ["three.js", "three.min.js"]
        }
        
        for lib, indicators in js_libraries.items():
            if any(indicator in content for indicator in indicators):
                tech_stack["javascript_libraries"].append(lib)
        
        # Analytics
        analytics_indicators = {
            "google analytics": ["google-analytics", "ga.js", "analytics.js"],
            "google tag manager": ["gtm.js", "googletagmanager"],
            "facebook pixel": ["facebook pixel", "fbq("],
            "hotjar": ["hotjar"],
            "matomo": ["matomo", "piwik.js"]
        }
        
        for analytic, indicators in analytics_indicators.items():
            if any(indicator in content for indicator in indicators):
                tech_stack["analytics"].append(analytic)
        
        # Clean empty categories
        tech_stack = {k: v for k, v in tech_stack.items() if v}
        
        if tech_stack:
            print(f"{Fore.CYAN}[TECH]{Style.RESET_ALL} {url}")
            for category, technologies in tech_stack.items():
                print(f"  {Fore.BLUE}• {category}:{Style.RESET_ALL} {', '.join(technologies)}")
        
        return tech_stack
        
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[TECH]{Style.RESET_ALL} Failed to detect technology for {url}: {e}")
        return {}

def technology_detection(urls):
    """Technology stack detection phase"""
    print(f"{Fore.CYAN}[PHASE 6]{Style.RESET_ALL} Technology Stack Detection")
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Detecting technologies for {len(urls)} URLs...")
    
    results = {}
    for url in list(urls):
        tech_stack = detect_technology(url)
        if tech_stack:
            results[url] = tech_stack
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Detected technologies for {len(results)} URLs")
    return results

# ---------------------------
# VULNERABILITY SCANNING FUNCTIONS (keep your existing ones)
# ---------------------------
def nuclei_scan(url):
    """Run Nuclei vulnerability scanning"""
    if not shutil.which("nuclei"):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Nuclei not installed. Skipping Nuclei scan.")
        return []
    
    try:
        print(f"{Fore.CYAN}[NUCLEI]{Style.RESET_ALL} Scanning {url}")
        cmd = ["nuclei", "-u", url, "-silent", "-json", "-severity", "low,medium,high,critical"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        vulnerabilities = []
        for line in result.stdout.splitlines():
            try:
                vuln = json.loads(line)
                vulnerabilities.append(vuln)
                
                template_id = vuln.get('template-id', 'unknown')
                severity = vuln.get('info', {}).get('severity', 'unknown').upper()
                name = vuln.get('info', {}).get('name', 'Unknown vulnerability')
                
                if severity == 'CRITICAL':
                    color = Fore.RED
                elif severity == 'HIGH':
                    color = Fore.RED
                elif severity == 'MEDIUM':
                    color = Fore.YELLOW
                elif severity == 'LOW':
                    color = Fore.BLUE
                else:
                    color = Fore.WHITE
                
                print(f"{color}[NUCLEI {severity}]{Style.RESET_ALL} {url}: {name} ({template_id})")
                
            except:
                pass
        
        return vulnerabilities
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[NUCLEI]{Style.RESET_ALL} Failed to scan {url}: {e}")
        return []

def check_takeover(subdomain):
    """Check for subdomain takeover"""
    try:
        ok, ips, cnames = dns_resolve_all(subdomain, args.timeout)
        if cnames:
            for cname in cnames:
                takeover_services = {
                    "s3.amazonaws.com": "AWS S3",
                    "cloudfront.net": "AWS CloudFront", 
                    "herokuapp.com": "Heroku",
                    "azurewebsites.net": "Azure App Service",
                    "github.io": "GitHub Pages",
                    "netlify.app": "Netlify",
                    "vercel.app": "Vercel",
                    "firebaseapp.com": "Firebase",
                    "surge.sh": "Surge",
                    "readthedocs.io": "ReadTheDocs"
                }
                
                for service, provider in takeover_services.items():
                    if service in cname:
                        return {
                            "type": "subdomain_takeover",
                            "severity": "HIGH",
                            "description": f"Potential {provider} takeover",
                            "evidence": f"CNAME: {cname}"
                        }
    except:
        pass
    return None

def check_security_headers(url):
    """Check security headers"""
    try:
        r = requests.get(url, timeout=args.timeout, verify=False)
        headers = r.headers
        
        issues = []
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection', 
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'XSS protection',
            'Referrer-Policy': 'Referrer information control'
        }
        
        for header, purpose in security_headers.items():
            if header not in headers:
                issues.append(f"Missing {header} - {purpose}")
        
        return issues
    except:
        return None

def check_xss_vulnerabilities(url):
    """Check for XSS vulnerabilities"""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "onmouseover=alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ]
    
    vulnerabilities = []
    
    parsed = urlparse(url)
    if parsed.query:
        for param in parsed.query.split('&'):
            key = param.split('=')[0]
            for payload in xss_payloads:
                test_url = url.replace(f"{key}={param.split('=')[1]}", f"{key}={payload}")
                try:
                    r = requests.get(test_url, timeout=args.timeout, verify=False)
                    if payload in r.text and "alert('XSS')" not in r.text:
                        vulnerabilities.append({
                            "type": "xss",
                            "severity": "HIGH", 
                            "description": "Reflected XSS vulnerability",
                            "evidence": f"Payload reflected: {payload}",
                            "url": test_url
                        })
                        break
                except:
                    pass
    
    return vulnerabilities

def check_sql_injection(url):
    """Check for SQL injection vulnerabilities"""
    sql_payloads = [
        "' OR '1'='1",
        "' UNION SELECT 1,2,3--",
        "' AND 1=1--",
        "'; DROP TABLE users--",
        "' OR 1=1--"
    ]
    
    sql_errors = [
        'sql syntax', 'mysql', 'oracle', 'sqlserver', 'postgresql',
        'microsoft odbc', 'driver', 'data source', 'database error',
        'procedure', 'column', 'unknown column', 'table', 'where clause'
    ]
    
    vulnerabilities = []
    
    parsed = urlparse(url)
    if parsed.query:
        for param in parsed.query.split('&'):
            key = param.split('=')[0]
            for payload in sql_payloads:
                test_url = url.replace(f"{key}={param.split('=')[1]}", f"{key}={payload}")
                try:
                    r = requests.get(test_url, timeout=args.timeout, verify=False)
                    response_lower = r.text.lower()
                    if any(error in response_lower for error in sql_errors):
                        vulnerabilities.append({
                            "type": "sql_injection",
                            "severity": "CRITICAL",
                            "description": "Potential SQL injection vulnerability",
                            "evidence": f"Database error with payload: {payload}",
                            "url": test_url
                        })
                        break
                except:
                    pass
    
    return vulnerabilities

def check_lfi_vulnerabilities(url):
    """Check for Local File Inclusion vulnerabilities"""
    lfi_payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd", 
        "../../../../windows/win.ini",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    ]
    
    lfi_indicators = ['root:', '[fonts]', '[extensions]', 'mysql', 'administrator']
    
    vulnerabilities = []
    
    parsed = urlparse(url)
    if parsed.query:
        for param in parsed.query.split('&'):
            key = param.split('=')[0]
            for payload in lfi_payloads:
                test_url = url.replace(f"{key}={param.split('=')[1]}", f"{key}={payload}")
                try:
                    r = requests.get(test_url, timeout=args.timeout, verify=False)
                    if any(content in r.text for content in lfi_indicators):
                        vulnerabilities.append({
                            "type": "lfi",
                            "severity": "HIGH",
                            "description": "Local File Inclusion vulnerability",
                            "evidence": f"File content leaked with: {payload}",
                            "url": test_url
                        })
                        break
                except:
                    pass
    
    return vulnerabilities

def vulnerability_scanning(subdomains, urls):
    """Complete vulnerability scanning phase"""
    print(f"{Fore.CYAN}[PHASE 5]{Style.RESET_ALL} Vulnerability Assessment")
    
    all_targets = list(set(list(subdomains) + [urlparse(url).netloc for url in urls]))
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanning {len(all_targets)} targets for vulnerabilities...")
    
    results = {
        "takeovers": {},
        "security_headers": {},
        "xss": {},
        "sql_injection": {}, 
        "lfi": {},
        "nuclei": {}
    }
    
    # Nuclei scanning
    if args.nuclei_scan:
        print(f"{Fore.CYAN}[NUCLEI]{Style.RESET_ALL} Running Nuclei vulnerability scans...")
        for subdomain in all_targets[:10]:  # Limit to 10 for performance
            url = f"https://{subdomain}"
            nuclei_results = nuclei_scan(url)
            if nuclei_results:
                results["nuclei"][subdomain] = nuclei_results
    
    # Subdomain takeover checks
    if args.takeover:
        print(f"{Fore.CYAN}[TAKEOVER]{Style.RESET_ALL} Checking for subdomain takeovers...")
        for subdomain in all_targets:
            takeover = check_takeover(subdomain)
            if takeover:
                results["takeovers"][subdomain] = takeover
                print(f"{Fore.RED}[TAKEOVER]{Style.RESET_ALL} {subdomain}: {takeover['description']}")
    
    # Security headers checks
    if args.headers:
        print(f"{Fore.CYAN}[HEADERS]{Style.RESET_ALL} Checking security headers...")
        for subdomain in all_targets[:10]:  # Limit to 10 for performance
            url = f"https://{subdomain}"
            missing_headers = check_security_headers(url)
            if missing_headers:
                results["security_headers"][subdomain] = missing_headers
                print(f"{Fore.YELLOW}[HEADERS]{Style.RESET_ALL} {subdomain}: {len(missing_headers)} security issues")
    
    # XSS scanning
    if args.xss_scan:
        print(f"{Fore.CYAN}[XSS]{Style.RESET_ALL} Checking for XSS vulnerabilities...")
        for url in list(urls)[:5]:  # Limit to 5 for performance
            xss_vulns = check_xss_vulnerabilities(url)
            if xss_vulns:
                results["xss"][url] = xss_vulns
                for vuln in xss_vulns:
                    print(f"{Fore.RED}[XSS]{Style.RESET_ALL} {url}: {vuln['description']}")
    
    # SQL injection scanning
    if args.sqli_scan:
        print(f"{Fore.CYAN}[SQLi]{Style.RESET_ALL} Checking for SQL injection...")
        for url in list(urls)[:5]:  # Limit to 5 for performance
            sql_vulns = check_sql_injection(url)
            if sql_vulns:
                results["sql_injection"][url] = sql_vulns
                for vuln in sql_vulns:
                    print(f"{Fore.RED}[SQLi]{Style.RESET_ALL} {url}: {vuln['description']}")
    
    # LFI scanning
    if args.lfi_scan:
        print(f"{Fore.CYAN}[LFI]{Style.RESET_ALL} Checking for LFI vulnerabilities...")
        for url in list(urls)[:5]:  # Limit to 5 for performance
            lfi_vulns = check_lfi_vulnerabilities(url)
            if lfi_vulns:
                results["lfi"][url] = lfi_vulns
                for vuln in lfi_vulns:
                    print(f"{Fore.RED}[LFI]{Style.RESET_ALL} {url}: {vuln['description']}")
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Vulnerability assessment completed")
    return results

# ---------------------------
# MAIN EXECUTION - ENHANCED
# ---------------------------
def run():
    """Enhanced main execution function with smart recon"""
    if not args.domain and not args.url and not args.input:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Please provide a domain (-d), URL (-u), or input file (-i)")
        return
        
    # Initialize enhanced components
    js_recon = JSRecon()
    
    # Normalize input
    targets = []
    if args.domain:
        targets.append(args.domain)
    elif args.url:
        parsed = urlparse(args.url)
        targets.append(parsed.netloc)  # Extract domain from URL
    elif args.input and os.path.exists(args.input):
        with open(args.input, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    
    # Initialize AI
    ai_system.setup_ai()
    
    targets = []
    if args.domain:
        targets.append(args.domain)
    elif args.url:
        targets.append(args.url)
    elif args.input and os.path.exists(args.input):
        with open(args.input, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    
    all_results = {}
    
    for target in targets:
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[TARGET]{Style.RESET_ALL} {target}")
        print(f"{Fore.CYAN}[AI MODE]{Style.RESET_ALL} {args.ai_mode.upper()}")
        print(f"{Fore.CYAN}[AI STATUS]{Style.RESET_ALL} {'Ollama Enabled' if ai_system.ollama_available else 'Heuristic AI'}")
        print(f"{Fore.CYAN}[WORKERS]{Style.RESET_ALL} {args.workers}")
        print(f"{Fore.CYAN}[RECURSION LEVELS]{Style.RESET_ALL} {args.levels}")
        print(f"{Fore.CYAN}[MAX SUBDOMAINS]{Style.RESET_ALL} Up to 75,000 in aggressive mode")
        print(f"{Fore.CYAN}[NUCLEI]{Style.RESET_ALL} {'Enabled' if args.nuclei_scan else 'Disabled'}")
        print(f"{Fore.CYAN}[TECH DETECTION]{Style.RESET_ALL} {'Enabled' if args.tech_detect else 'Disabled'}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        target_results = {"target": target}
        all_subs = set()
        all_urls = set()
        
        # PHASE 1: Passive Reconnaissance
        if args.passive or args.subdomains or args.recon or args.full_scan:
            print(f"\n{Fore.CYAN}[PHASE 1]{Style.RESET_ALL} Passive Reconnaissance")
            passive_subs = passive_reconnaissance(target)
            target_results["passive_subdomains"] = list(passive_subs)
            all_subs.update(passive_subs)
        
        # PHASE 2: Active Reconnaissance (with recursion)
        if args.active or args.subdomains or args.recon or args.full_scan:
            print(f"\n{Fore.CYAN}[PHASE 2]{Style.RESET_ALL} Active Reconnaissance")
            active_subs = active_reconnaissance(target, passive_subs if 'passive_subs' in locals() else set())
            target_results["active_subdomains"] = list(active_subs)
            all_subs.update(active_subs)
        
        target_results["all_subdomains"] = list(all_subs)
        
        # Collect all live URLs from subdomains
        for subdomain in all_subs:
            all_urls.add(f"https://{subdomain}")
            all_urls.add(f"http://{subdomain}")
        
        # PHASE 3: Port Scanning
        if args.portscan or args.scan or args.full_scan:
            if all_subs:
                print(f"\n{Fore.CYAN}[PHASE 3]{Style.RESET_ALL} Port Scanning")
                port_results = port_scanning(all_subs)
                target_results["port_scan"] = port_results
            else:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No subdomains found for port scanning")
        
        # PHASE 4: Directory Scanning - ENHANCED TO SCAN ALL URLS
        if args.dirscan or args.scan or args.full_scan:
            if all_urls:
                print(f"\n{Fore.CYAN}[PHASE 4]{Style.RESET_ALL} Directory Scanning")
                dir_results = directory_scanning(all_urls)  # Now scans ALL URLs
                target_results["directory_scan"] = dir_results
                # Add discovered URLs to all_urls for further scanning
                for url, paths in dir_results.items():
                    for path in paths:
                        all_urls.add(path["url"])
            else:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No URLs found for directory scanning")
        
        # PHASE 4.5: Website Crawling - ENHANCED TO CRAWL ALL URLS
        if args.crawl or args.scan or args.full_scan:
            if args.url:  # Check for direct URL mode
                print(f"\n{Fore.CYAN}[PHASE 4.5]{Style.RESET_ALL} Website Crawling")
                url_results = website_crawling(args.url)
                target_results["crawling"] = url_results
                # Add crawled URLs to all_urls
                for url, crawled_urls in url_results.items():
                    all_urls.update(crawled_urls)
            elif all_urls:  # Fallback to scanning discovered URLs
                print(f"\n{Fore.CYAN}[PHASE 4.5]{Style.RESET_ALL} Website Crawling")
                crawl_results = website_crawling(all_urls)
                target_results["crawling"] = crawl_results
                # Add crawled URLs to all_urls
                for url, crawled_urls in crawl_results.items():
                    all_urls.update(crawled_urls)
            else:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No URLs found for crawling")
        
        # PHASE 5: Vulnerability Assessment
        if args.vuln_scan or args.nuclei_scan or args.takeover or args.headers or args.xss_scan or args.sqli_scan or args.lfi_scan or args.full_scan:
            if all_subs or all_urls:
                print(f"\n{Fore.CYAN}[PHASE 5]{Style.RESET_ALL} Vulnerability Assessment")
                vuln_results = vulnerability_scanning(all_subs, list(all_urls))
                target_results["vulnerabilities"] = vuln_results
            else:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No targets found for vulnerability scanning")
        
        # PHASE 6: Technology Detection
        if args.tech_detect or args.full_tech_scan or args.full_scan:
            if all_urls:
                print(f"\n{Fore.CYAN}[PHASE 6]{Style.RESET_ALL} Technology Stack Detection")
                tech_results = technology_detection(all_urls)
                target_results["technology_stack"] = tech_results
            else:
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No URLs found for technology detection")
        
        all_results[target] = target_results
        
        # Save results
        if args.output and all_subs:
            with open(args.output, 'w') as f:
                for subdomain in all_subs:
                    f.write(f"{subdomain}\n")
            print(f"{Fore.GREEN}[SAVED]{Style.RESET_ALL} Subdomains saved to {args.output}")
        
        if args.json_output:
            with open(args.json_output, 'w') as f:
                json.dump(all_results, f, indent=2)
            print(f"{Fore.GREEN}[SAVED]{Style.RESET_ALL} Full results saved to {args.json_output}")
    
    # Final Summary
    print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{' SCAN COMPLETE ':.^80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    
    total_subdomains = 0
    total_vulns = 0
    total_tech_detected = 0
    
    for target, results in all_results.items():
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {target}")
        
        subs_count = len(results.get('all_subdomains', []))
        total_subdomains += subs_count
        print(f"{Fore.CYAN}Subdomains Found:{Style.RESET_ALL} {subs_count}")
        
        if 'port_scan' in results:
            open_hosts = len(results['port_scan'])
            print(f"{Fore.CYAN}Hosts with Open Ports:{Style.RESET_ALL} {open_hosts}")
        
        if 'technology_stack' in results:
            tech_count = len(results['technology_stack'])
            total_tech_detected += tech_count
            print(f"{Fore.CYAN}Technology Stacks Detected:{Style.RESET_ALL} {tech_count}")
        
        if 'vulnerabilities' in results:
            vuln_data = results['vulnerabilities']
            
            # Count all vulnerability types
            vuln_count = (
                len(vuln_data.get('takeovers', {})) +
                len(vuln_data.get('xss', {})) +
                len(vuln_data.get('sql_injection', {})) +
                len(vuln_data.get('lfi', {})) +
                sum(len(vulns) for vulns in vuln_data.get('nuclei', {}).values())
            )
            total_vulns += vuln_count
            
            if vuln_count > 0:
                print(f"{Fore.RED}Vulnerabilities Found:{Style.RESET_ALL} {vuln_count}")
                
                # Show breakdown
                if vuln_data.get('takeovers'):
                    print(f"  {Fore.RED}• Subdomain Takeovers:{Style.RESET_ALL} {len(vuln_data['takeovers'])}")
                if vuln_data.get('nuclei'):
                    nuclei_count = sum(len(vulns) for vulns in vuln_data['nuclei'].values())
                    print(f"  {Fore.RED}• Nuclei Findings:{Style.RESET_ALL} {nuclei_count}")
                if vuln_data.get('xss'):
                    print(f"  {Fore.RED}• XSS Vulnerabilities:{Style.RESET_ALL} {len(vuln_data['xss'])}")
                if vuln_data.get('sql_injection'):
                    print(f"  {Fore.RED}• SQL Injection:{Style.RESET_ALL} {len(vuln_data['sql_injection'])}")
                if vuln_data.get('lfi'):
                    print(f"  {Fore.RED}• LFI Vulnerabilities:{Style.RESET_ALL} {len(vuln_data['lfi'])}")
            else:
                print(f"{Fore.GREEN}Vulnerabilities Found:{Style.RESET_ALL} 0")
        
        print()
    
    print(f"{Fore.GREEN}Total Subdomains Found:{Style.RESET_ALL} {total_subdomains}")
    print(f"{Fore.CYAN}Technology Stacks Detected:{Style.RESET_ALL} {total_tech_detected}")
    print(f"{Fore.RED}Total Vulnerabilities Found:{Style.RESET_ALL} {total_vulns}")
    
    if ai_system.ollama_available:
        print(f"\n{Fore.MAGENTA}[AI]{Style.RESET_ALL} Ollama AI was used for intelligent subdomain selection and recursive discovery")
        print(f"{Fore.MAGENTA}[AI]{Style.RESET_ALL} AI Mode: {args.ai_mode.upper()} - Tested up to 75K subdomains with {args.levels} recursion levels")
    else:
        print(f"\n{Fore.CYAN}[AI]{Style.RESET_ALL} Heuristic AI was used - Tested up to 75K subdomains with {args.levels} recursion levels")

if __name__ == "__main__":
    run()
