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

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
    print(f"{Fore.YELLOW}[!] tqdm not installed. Progress bars disabled. Install with: pip install tqdm{Style.RESET_ALL}")

# Silencing insecure warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tool metadata
__version__ = "1.0.0"
__author__ = "Suman Das"
__license__ = "MIT"

# ---------------------------
# RETRY LOGIC & RATE LIMITING
# ---------------------------
from functools import wraps
from typing import Callable, Any

class RateLimiter:
    """Rate limiter to control requests per second"""
    def __init__(self, max_requests_per_second=5.0):
        self.max_requests_per_second = max_requests_per_second
        self.min_interval = 1.0 / max_requests_per_second if max_requests_per_second > 0 else 0
        self.last_request_time = 0
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        """Wait if necessary to respect rate limit"""
        if self.max_requests_per_second <= 0:
            return
        
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()

# Global rate limiter instance
rate_limiter = None  # Will be initialized after args parsing

def retry_on_failure(max_attempts=3, backoff_factor=2, exceptions=(requests.RequestException, socket.timeout)):
    """
    Decorator for retrying failed requests with exponential backoff
    
    Args:
        max_attempts: Maximum number of retry attempts (default: 3)
        backoff_factor: Multiplier for exponential backoff (default: 2)
        exceptions: Tuple of exceptions to catch and retry
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    # Apply rate limiting before request
                    if rate_limiter:
                        rate_limiter.wait_if_needed()
                    
                    result = func(*args, **kwargs)
                    return result
                    
                except exceptions as e:
                    last_exception = e
                    
                    # Don't retry on 404, 403, 401 (client errors)
                    if hasattr(e, 'response') and e.response is not None:
                        if e.response.status_code in [404, 403, 401]:
                            raise e
                    
                    if attempt < max_attempts - 1:
                        # Exponential backoff: 1s, 2s, 4s, 8s...
                        wait_time = backoff_factor ** attempt
                        
                        # Add jitter to avoid thundering herd
                        jitter = random.uniform(0, 0.1 * wait_time)
                        total_wait = wait_time + jitter
                        
                        if args and hasattr(args[0], 'verbose') and args[0].verbose:
                            print(f"{Fore.YELLOW}[RETRY]{Style.RESET_ALL} Attempt {attempt + 1}/{max_attempts} failed, retrying in {total_wait:.2f}s...")
                        
                        time.sleep(total_wait)
                    else:
                        # Last attempt failed
                        if args and hasattr(args[0], 'verbose') and args[0].verbose:
                            print(f"{Fore.RED}[RETRY]{Style.RESET_ALL} All {max_attempts} attempts failed: {e}")
                
                except Exception as e:
                    # Don't retry on non-network exceptions
                    raise e
            
            # All retries exhausted
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator

def safe_request_get(url, timeout=3.0, verify=False, headers=None, allow_redirects=True, max_retries=3):
    """
    Safe HTTP GET request with built-in retry logic and rate limiting
    
    Args:
        url: URL to request
        timeout: Request timeout in seconds
        verify: SSL verification
        headers: Request headers
        allow_redirects: Follow redirects
        max_retries: Maximum retry attempts
    
    Returns:
        requests.Response object or None on failure
    """
    @retry_on_failure(max_attempts=max_retries)
    def _make_request():
        return requests.get(
            url, 
            timeout=timeout, 
            verify=verify, 
            headers=headers or {}, 
            allow_redirects=allow_redirects
        )
    
    try:
        return _make_request()
    except Exception as e:
        return None

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
parser.add_argument("--csv-output", help="CSV output file for JS recon findings")
parser.add_argument("--html-output", help="HTML report file for JS recon findings")
parser.add_argument("--verbose", action="store_true", help="Verbose logging")
parser.add_argument("--log-file", help="Log file path (default: sfuzz.log)")
parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    help="Logging level (default: INFO)")

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
parser.add_argument("--jsrecon", action="store_true", help="Extract and analyze JavaScript files for endpoints, secrets and sensitive info")

# Modern Reconnaissance (2025)
parser.add_argument("--waf-detect", action="store_true", help="WAF/CDN detection & fingerprinting (27+ signatures)")
parser.add_argument("--cloud-detect", action="store_true", help="Cloud provider & storage bucket detection (AWS, Azure, GCP)")
parser.add_argument("--cloud-vuln", action="store_true", help="AI-powered cloud vulnerability scanning (requires --cloud-detect)")
parser.add_argument("--takeover-scan", action="store_true", help="Subdomain takeover vulnerability detection (15+ services)")
parser.add_argument("--takeover-poc", action="store_true", help="Generate PoC steps for detected takeovers")
parser.add_argument("--api-scan", action="store_true", help="API endpoint discovery (REST, GraphQL, OpenAPI)")
parser.add_argument("--container-scan", action="store_true", help="Container infrastructure detection (Docker, Kubernetes)")
parser.add_argument("--graphql-introspect", action="store_true", help="Enhanced GraphQL schema introspection")

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
    args.cloud_detect = args.api_scan = args.container_scan = True  # Enable modern recon
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
# Initialize Rate Limiter
# ---------------------------
rate_limiter = RateLimiter(max_requests_per_second=args.rate)

# ---------------------------
# Setup Structured Logging
# ---------------------------
import logging
from logging.handlers import RotatingFileHandler

# Determine log level
log_level = getattr(logging, args.log_level.upper(), logging.INFO)
if args.verbose:
    log_level = logging.DEBUG

# Create logger
logger = logging.getLogger('sfuzz')
logger.setLevel(log_level)

# Remove existing handlers
logger.handlers = []

# Console handler (colorized output)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(log_level)
console_format = logging.Formatter(
    f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_handler.setFormatter(console_format)
logger.addHandler(console_handler)

# File handler (rotating logs)
if args.log_file or True:  # Always create log file
    log_file_path = args.log_file or 'sfuzz.log'
    file_handler = RotatingFileHandler(
        log_file_path, 
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
# Don't propagate to root logger
logger.propagate = False

# Helper function to maintain backward compatibility with print statements
def log_info(msg):
    logger.info(msg)

def log_debug(msg):
    logger.debug(msg)

def log_warning(msg):
    logger.warning(msg)

def log_error(msg):
    logger.error(msg)

def log_critical(msg):
    logger.critical(msg)

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
        # Apply rate limiting before HTTP requests
        if rate_limiter:
            rate_limiter.wait_if_needed()
        
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
                r = safe_request_get(url, headers=headers, timeout=args.timeout, max_retries=2)
                
                if r and r.status_code < 500:  # Consider any non-server-error as live
                    add_live_subdomain(subdomain, r.status_code, 'httpx')
                    add_live_url(url, r.status_code, 'httpx')
                    
                    # Also check common ports for this subdomain
                    if r.status_code == 200:
                        common_alt_ports = [8080, 8443, 3000, 5000, 8000]
                        for port in common_alt_ports:
                            alt_url = f"{scheme}://{subdomain}:{port}/"
                            try:
                                r_alt = safe_request_get(alt_url, headers=headers, timeout=2, max_retries=1)
                                if r_alt and r_alt.status_code < 500:
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
        with tqdm(total=len(futures), desc="HTTP Probing", unit="host") as pbar:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.add(result)
                pbar.update(1)    
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
        r = safe_request_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        r = safe_request_get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names", 
                        timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        r = safe_request_get(url, timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        r = safe_request_get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        r = safe_request_get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", 
                        timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        r = safe_request_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        r = safe_request_get(f"https://api.subdomain.center/?domain={domain}", timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        r = safe_request_get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=args.timeout, max_retries=3)
        if r and r.status_code == 200:
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
        with tqdm(total=len(api_collectors), desc="API Sources", unit="src") as pbar:
            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_subs.update(results)
                except Exception as e:
                    if args.verbose:
                        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} API collector failed: {e}")
                pbar.update(1)
    
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
        
        # Apply rate limiting before DNS query
        if rate_limiter:
            rate_limiter.wait_if_needed()
        
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
        
        with tqdm(total=len(futures), desc=f"Level {current_level} DNS", unit="sub") as pbar:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subs.add(result)
                pbar.update(1)    
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
                with tqdm(total=len(futures), desc="Recursive DNS", unit="sub") as pbar:
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            recursive_subs.add(result)
                        pbar.update(1)            
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

def website_crawling(urls):
    """Enhanced website crawling phase with AI path prediction"""
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
    return results

# ---------------------------
# JAVASCRIPT RECONNAISSANCE
class JSRecon:
    """Enhanced JavaScript analysis and reconnaissance module"""
    
    def __init__(self):
        # Initialize basic collections
        self.discovered_endpoints = set() # URLs and endpoints
        self.js_files = set() # JavaScript files
        self.api_patterns = set() # API patterns
        self.secrets = [] # Secrets and keys - changed to list to track source
        self.frameworks = {} # Framework versions
        self.functions = set() # Function names
        self.event_handlers = set() # Event handlers 
        self.ajax_calls = set() # AJAX calls
        self.websockets = set() # WebSocket endpoints
        
        # NEW: Enhanced detection
        self.main_functions = {} # Main application functions with usage count
        self.crypto_implementations = [] # Encryption/crypto logic found
        self.vulnerable_libs = [] # Outdated/vulnerable libraries
        self.library_versions = {} # Detected library versions
        self.ai_insights = [] # AI-generated security insights
        
        # ADVANCED: Supply Chain & Dependencies
        self.supply_chain_risks = [] # Malicious/compromised dependencies
        self.missing_sri = [] # Resources without SRI hashes
        self.typosquatting_risks = [] # Suspicious package names
        
        # ADVANCED: XSS & Injection Vulnerabilities
        self.dom_xss_sinks = [] # Dangerous DOM XSS sinks
        self.csti_vulns = [] # Client-side template injection
        self.prototype_pollution = [] # Prototype pollution vulnerabilities
        
        # ADVANCED: Advanced Secret Detection
        self.high_entropy_secrets = [] # High entropy strings (likely secrets)
        self.private_keys = [] # RSA/SSH/PGP private keys
        self.source_maps = [] # Exposed source map files
        
        # ADVANCED: API & Communication
        self.graphql_endpoints = [] # GraphQL endpoints
        self.postmessage_issues = [] # PostMessage security issues
        self.websocket_endpoints = [] # WebSocket connections
        self.ssrf_vectors = [] # Potential SSRF vulnerabilities
        
        # ADVANCED: Storage & Privacy
        self.storage_exposure = [] # localStorage/sessionStorage issues
        self.fingerprinting = [] # Browser fingerprinting techniques
        
        # ADVANCED: Modern Web Tech
        self.wasm_modules = [] # WebAssembly modules
        self.service_workers = [] # Service worker implementations
        self.webrtc_leaks = [] # WebRTC IP leak vectors
        
        # ADVANCED: Code Analysis
        self.obfuscated_code = [] # Obfuscated JavaScript
        self.weak_crypto = [] # Weak cryptographic implementations
        self.clickjacking_vectors = [] # Clickjacking vulnerabilities
        self.cors_issues = [] # CORS misconfigurations
        
        # HTTP request headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close'
        }
        
        # Regex patterns for scanning
        self.endpoint_patterns = {
            'api': r'[\'"]\/(?:api|v\d+)\/[^\'"]+[\'"]',
            'urls': r'[\'"]https?:\/\/[^\'"]+[\'"]',
            'paths': r'[\'"]\/?[\w-]+\/[^\'"]+[\'"]'
        }
        
        self.framework_patterns = {
            'angular': r'angular\.version\.full\s*=\s*[\'"]([^\'"]+)[\'"]',
            'react': r'React\.version\s*=\s*[\'"]([^\'"]+)[\'"]', 
            'vue': r'Vue\.version\s*=\s*[\'"]([^\'"]+)[\'"]',
            'jquery': r'\$\.fn\.jquery\s*=\s*[\'"]([^\'"]+)[\'"]'
        }
        
        self.secret_patterns = {
            'api_key': r'(?i)api[_-]?key\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            'access_token': r'(?i)access[_-]?token\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            'password': r'(?i)password\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
            'secret': r'(?i)secret\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
        }
        
    def analyze_js(self, target_url):
        """Main JavaScript analysis method with enhanced error handling"""
        try:
            print(f"{Fore.CYAN}[JS-RECON]{Style.RESET_ALL} Analyzing JavaScript content from {target_url}")
            
            # Check if BeautifulSoup is available
            if not BeautifulSoup:
                print(f"{Fore.RED}[JS-RECON]{Style.RESET_ALL} BeautifulSoup not available. Install with: pip install beautifulsoup4")
                return None
            
            # Make initial request with proper headers and retry logic
            if args.verbose:
                print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} Making initial request to {target_url}")
            
            response = safe_request_get(target_url, timeout=args.timeout, headers=self.headers, allow_redirects=True, max_retries=3)
            
            if response is None:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Failed to fetch {target_url} after retries")
                return None
            
            if args.verbose:
                print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} Response status: {response.status_code}")
                print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} Content-Type: {response.headers.get('content-type', 'unknown')}")
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Count script tags
                all_scripts = soup.find_all('script')
                external_scripts = soup.find_all('script', src=True)
                inline_scripts = [s for s in all_scripts if s.string]
                
                if args.verbose:
                    print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} Found {len(all_scripts)} total script tags")
                    print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} External scripts: {len(external_scripts)}, Inline scripts: {len(inline_scripts)}")
                
                # First detect frameworks from main page
                self._detect_frameworks(response.text, response.headers)
                if self.frameworks:
                    print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Detected Frameworks:")
                    for framework, version in self.frameworks.items():
                        print(f"{Fore.CYAN}[FRAMEWORK]{Style.RESET_ALL} {framework} v{version}")
                elif args.verbose:
                    print(f"{Fore.YELLOW}[DEBUG]{Style.RESET_ALL} No frameworks detected in main page")
                
                # Check for CORS misconfigurations on main URL
                if args.verbose:
                    print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} Testing CORS configuration...")
                self._detect_cors_issues(target_url)
                
                # Find and analyze script tags
                scripts = []
                
                # External scripts
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    original_src = src
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif not src.startswith(('http://', 'https://')):
                        src = urljoin(target_url, src)
                    scripts.append(src)
                    if args.verbose:
                        print(f"{Fore.CYAN}[DEBUG]{Style.RESET_ALL} Found script: {original_src} -> {src}")
                    
                # Inline scripts analysis
                if inline_scripts:
                    print(f"{Fore.CYAN}[JS-RECON]{Style.RESET_ALL} Analyzing {len(inline_scripts)} inline scripts...")
                    for script in inline_scripts:
                        if script.string and len(script.string.strip()) > 0:
                            self._extract_functions(script.string)
                            self._extract_event_handlers(script.string)
                            self._find_ajax_calls(script.string)
                            self._extract_endpoints(script.string, target_url)
                            self._scan_sensitive_data(script.string)
                elif args.verbose:
                    print(f"{Fore.YELLOW}[DEBUG]{Style.RESET_ALL} No inline scripts found")
                
                # Process external scripts with retry logic
                if scripts:
                    print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Analyzing {len(scripts)} external JavaScript files...")
                    
                    # Create progress bar if tqdm is available
                    script_iterator = tqdm(scripts, desc="Analyzing JS files", unit="file", ncols=100, disable=not tqdm) if tqdm else scripts
                    
                    for script in script_iterator:
                        try:
                            # Use safe_request_get with retry logic and rate limiting
                            r = safe_request_get(script, timeout=args.timeout, headers=self.headers, max_retries=3)
                            
                            if r and r.status_code == 200:
                                if not tqdm:  # Only print if no progress bar
                                    print(f"{Fore.CYAN}[JS-FILE]{Style.RESET_ALL} Analyzing: {script}")
                                self.js_files.add(script)
                                
                                # Extract all information
                                content = r.text
                                self._detect_frameworks(content, r.headers)
                                self._extract_functions(content)
                                self._extract_event_handlers(content)
                                self._find_ajax_calls(content)
                                self._extract_endpoints(content, script)
                                self._scan_sensitive_data(content, script)
                                self._find_imports(content, script)
                                # NEW: Enhanced analysis
                                self._detect_main_functions(content, script)
                                self._detect_crypto_logic(content, script)
                                self._detect_vulnerable_libraries(content, script)
                                
                                # ADVANCED: Supply Chain & Security
                                self._check_supply_chain_risks(script, content)
                                self._detect_dom_xss_sinks(content, script)
                                self._detect_prototype_pollution(content, script)
                                self._detect_csti_vulnerabilities(content, script)
                                
                                # ADVANCED: Secret & Key Detection
                                self._detect_high_entropy_secrets(content, script)
                                self._detect_private_keys(content, script)
                                self._check_source_maps(script)
                                
                                # ADVANCED: API & Communication
                                self._detect_graphql(content, script)
                                self._detect_postmessage_issues(content, script)
                                self._detect_ssrf_vectors(content, script)
                                
                                # ADVANCED: Storage & Privacy
                                self._detect_storage_exposure(content, script)
                                self._detect_fingerprinting(content, script)
                                
                                # ADVANCED: Modern Tech
                                self._detect_wasm(content, script)
                                self._detect_service_workers(content, script)
                                self._detect_webrtc_leaks(content, script)
                                
                                # ADVANCED: Code Analysis
                                self._detect_obfuscation(content, script)
                                self._detect_weak_crypto(content, script)
                                self._detect_clickjacking(content, script)
                                
                                # NEW: AI-powered analysis (run once on first substantial file)
                                if not self.ai_insights and len(content) > 1000 and ai_system.ollama_available:
                                    self._ai_analyze_javascript(content, script)
                                
                        except Exception as e:
                            if args.verbose:
                                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Failed to analyze {script}: {e}")
                
                # AI-enhanced analysis if available
                if ai_system.ollama_available:
                    prompt = f"""
                    Analyze this JavaScript for security-relevant items:
                    1. Hidden API endpoints
                    2. Authentication flows
                    3. Sensitive variables
                    4. Potential vulnerabilities
                    
                    URL: {target_url}
                    Frameworks: {', '.join(f'{k} v{v}' for k,v in self.frameworks.items())}
                    """
                    
                    findings = ai_system.query_ollama(prompt)
                    if findings:
                        print(f"\n{Fore.GREEN}[AI-ANALYSIS]{Style.RESET_ALL} Additional findings:")
                        for line in findings.splitlines():
                            if line.strip():
                                print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} {line.strip()}")
                
                # Cleanup: Update vulnerable_libs with actual detected versions
                self._update_vulnerable_libs_with_detected_versions()
                
                # Display findings
                self._display_findings()
                
                return {
                    'frameworks': self.frameworks,
                    'functions': list(self.functions),
                    'event_handlers': list(self.event_handlers),
                    'ajax_calls': list(self.ajax_calls),
                    'websockets': list(self.websockets),
                    'endpoints': list(self.discovered_endpoints),
                    'api_patterns': list(self.api_patterns),
                    'js_files': list(self.js_files),
                    'secrets': list(self.secrets)
                }
            else:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Received status code: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"{Fore.RED}[JS-RECON]{Style.RESET_ALL} Analysis failed: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return None

    def _extract_functions(self, content):
        """Extract JavaScript function definitions"""
        # Function declarations and expressions
        patterns = [
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)',  # Function declarations
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\([^)]*\)',  # Function expressions
            r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\([^)]*\)\s*=>', # Arrow functions
            r'(?:class|interface)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', # Classes and interfaces
            r'(?:get|set)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)' # Getters and setters
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.functions.add(match.group(1))
                
    def _find_ajax_calls(self, content):
        """Extract AJAX and WebSocket connections"""
        # AJAX patterns
        ajax_patterns = [
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',  # jQuery AJAX
            r'fetch\s*\([\'"`]([^\'"`]+)[\'"`]',  # Fetch API
            r'\$\.(?:get|post|put|delete)\s*\([\'"`]([^\'"`]+)[\'"`]',  # jQuery HTTP methods
            r'axios\.(?:get|post|put|delete)\s*\([\'"`]([^\'"`]+)[\'"`]',  # Axios
            r'new XMLHttpRequest\(\).*?\.open\s*\([^,]+,[\'"`]([^\'"`]+)[\'"`]' # XMLHttpRequest
        ]
        
        for pattern in ajax_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.ajax_calls.add(match.group(1))
                
        # WebSocket patterns
        ws_patterns = [
            r'new WebSocket\s*\([\'"`]((?:ws|wss)://[^\'"`]+)[\'"`]\)',
            r'new ReconnectingWebSocket\s*\([\'"`]((?:ws|wss)://[^\'"`]+)[\'"`]\)',
            r'\.connect\s*\([\'"`]((?:ws|wss)://[^\'"`]+)[\'"`]\)'
        ]
        
        for pattern in ws_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.websockets.add(match.group(1))
                
    def _extract_event_handlers(self, content):
        """Extract event handler and listener registrations"""
        patterns = [
            r'\.addEventListener\s*\([\'"`](\w+)[\'"`]',  # addEventListener
            r'\.on\s*\([\'"`](\w+)[\'"`]',  # .on() handlers
            r'on\w+\s*=\s*[\'"`]([^\'"`]+)[\'"`]',  # inline handlers
            r'@(\w+)=[\'"`]([^\'"`]+)[\'"`]'  # Angular/Vue event bindings
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                if len(match.groups()) == 2:
                    self.event_handlers.add(f"{match.group(1)}={match.group(2)}")
                else:
                    self.event_handlers.add(match.group(1))

# analyze_js method already defined at the top

    def _detect_frameworks(self, content, headers):
        """Detect JavaScript frameworks and their versions"""
        content_str = str(content).lower()
        headers_str = str(headers).lower()

        # Framework detection patterns
        framework_patterns = {
            'react': {
                'patterns': [
                    r'react(?:[-_]dom)?(?:\.production|\.development)?\.min\.js(?:\?v=([0-9.]+))?',
                    r'"react":.*?"version":\s*"([0-9.]+)"',
                    r'__REACT_VERSION__\s*=\s*[\'"]([0-9.]+)[\'"]',
                    r'React\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['react', 'reactdom', '__REACT_ROOT__', 'window.React', 'ReactDOM']
            },
            'angular': {
                'patterns': [
                    r'angular(?:[-_]core)?(?:\.min)?\.js(?:\?v=([0-9.]+))?',
                    r'angular.*?version[\'"]?\s*[:=]\s*[\'"]([0-9.]+)[\'"]',
                    r'ng-version="([0-9.]+)"',
                    r'angular\.version\.full\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['angular', 'ng-app', 'ng-controller']
            },
            'vue': {
                'patterns': [
                    r'vue(?:\.runtime)?(?:\.esm)?(?:\.min)?\.js(?:\?v=([0-9.]+))?',
                    r'vue\.version\s*=\s*[\'"]([0-9.]+)[\'"]',
                    r'"vue":.*?"version":\s*"([0-9.]+)"'
                ],
                'indicators': ['vue', '__vue__', 'vuejs', 'Vue.createApp', 'new Vue']
            },
            'jquery': {
                'patterns': [
                    r'jquery[.-]([0-9.]+)(?:\.min)?\.js',
                    r'jquery\.fn\.jquery\s*=\s*[\'"]([0-9.]+)[\'"]',
                    r'"jquery":\s*"([0-9.]+)"'
                ],
                'indicators': ['jquery', '$', 'jquery.fn']
            },
            'backbone': {
                'patterns': [
                    r'backbone[.-]([0-9.]+)(?:\.min)?\.js',
                    r'Backbone\.VERSION\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['backbone.js', 'backbone-min.js']
            },
            'ember': {
                'patterns': [
                    r'ember[.-]([0-9.]+)(?:\.min)?\.js',
                    r'Ember\.VERSION\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['ember.js', 'ember-template-compiler']
            },
            'knockout': {
                'patterns': [
                    r'knockout[.-]([0-9.]+)(?:\.min)?\.js',
                    r'ko\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['knockout.js', 'ko.']
            },
            'next': {
                'patterns': [
                    r'/_next/static/([^/]+)/',
                    r'"next":.*?"version":\s*"([0-9.]+)"'
                ],
                'indicators': ['__next', 'next-route', '_next/static']
            },
            'nuxt': {
                'patterns': [
                    r'/_nuxt/([^/]+)/',
                    r'"nuxt":.*?"version":\s*"([0-9.]+)"'
                ],
                'indicators': ['__nuxt', '_nuxt', 'nuxt-link']
            },
            'lodash': {
                'patterns': [
                    r'lodash[.-]([0-9.]+)(?:\.min)?\.js',
                    r'lodash\.VERSION\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['lodash.js', '_.']
            },
            'moment': {
                'patterns': [
                    r'moment[.-]([0-9.]+)(?:\.min)?\.js',
                    r'moment\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['moment.js', 'moment-with-locales']
            },
            'socket.io': {
                'patterns': [
                    r'socket\.io[.-]([0-9.]+)(?:\.min)?\.js',
                    r'io\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['socket.io.js', 'io.connect']
            },
            'd3': {
                'patterns': [
                    r'd3[.-]([0-9.]+)(?:\.min)?\.js',
                    r'd3\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['d3.js', 'd3-']
            },
            'bootstrap': {
                'patterns': [
                    r'bootstrap[.-]([0-9.]+)(?:\.min)?\.js',
                    r'bootstrap/([0-9.]+)/',
                    r'"bootstrap":\s*"([0-9.]+)"'
                ],
                'indicators': ['bootstrap', 'navbar-toggler', 'container-fluid']
            }
        }

        # Detect frameworks and their versions
        for framework, data in framework_patterns.items():
            # First try to find version using patterns
            version_found = False
            for pattern in data['patterns']:
                matches = re.findall(pattern, content_str, re.IGNORECASE)
                if matches:
                    self.frameworks[framework] = matches[0]
                    version_found = True
                    break

            # If no version found but indicators present, mark as detected 
            if not version_found and any(indicator in content_str or indicator in headers_str 
                                       for indicator in data['indicators']):
                self.frameworks[framework] = 'version unknown'
    def _detect_frameworks(self, content, headers):
        """Detect JavaScript frameworks and versions"""
        content_str = str(content).lower()
        headers_str = str(headers).lower()

        # Framework detection patterns
        framework_patterns = {
            'react': {
                'patterns': [
                    r'react(?:[-_]dom)?(?:\.production|\.development)?\.min\.js(?:\?v=([0-9.]+))?',
                    r'"react":.*?"version":\s*"([0-9.]+)"',
                    r'__REACT_VERSION__\s*=\s*[\'"]([0-9.]+)[\'"]',
                    r'React\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['react', 'reactdom', '__REACT_ROOT__', 'window.React', 'ReactDOM']
            },
            'angular': {
                'patterns': [
                    r'angular(?:[-_]core)?(?:\.min)?\.js(?:\?v=([0-9.]+))?',
                    r'angular.*?version[\'"]?\s*[:=]\s*[\'"]([0-9.]+)[\'"]',
                    r'ng-version="([0-9.]+)"',
                    r'angular\.version\.full\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['angular', 'ng-app', 'ng-controller']
            },
            'vue': {
                'patterns': [
                    r'vue(?:\.runtime)?(?:\.esm)?(?:\.min)?\.js(?:\?v=([0-9.]+))?',
                    r'vue\.version\s*=\s*[\'"]([0-9.]+)[\'"]',
                    r'"vue":.*?"version":\s*"([0-9.]+)"'
                ],
                'indicators': ['vue', '__vue__', 'vuejs', 'Vue.createApp', 'new Vue']
            },
            'jquery': {
                'patterns': [
                    r'jquery[.-]([0-9.]+)(?:\.min)?\.js',
                    r'jquery\.fn\.jquery\s*=\s*[\'"]([0-9.]+)[\'"]',
                    r'"jquery":\s*"([0-9.]+)"'
                ],
                'indicators': ['jquery', '$', 'jquery.fn']
            },
            'backbone': {
                'patterns': [
                    r'backbone[.-]([0-9.]+)(?:\.min)?\.js',
                    r'Backbone\.VERSION\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['backbone.js', 'backbone-min.js']
            },
            'ember': {
                'patterns': [
                    r'ember[.-]([0-9.]+)(?:\.min)?\.js',
                    r'Ember\.VERSION\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['ember.js', 'ember-template-compiler']
            },
            'knockout': {
                'patterns': [
                    r'knockout[.-]([0-9.]+)(?:\.min)?\.js',
                    r'ko\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['knockout.js', 'ko.']
            },
            'next': {
                'patterns': [
                    r'/_next/static/([^/]+)/',
                    r'"next":.*?"version":\s*"([0-9.]+)"'
                ],
                'indicators': ['__next', 'next-route', '_next/static']
            },
            'nuxt': {
                'patterns': [
                    r'/_nuxt/([^/]+)/',
                    r'"nuxt":.*?"version":\s*"([0-9.]+)"'
                ],
                'indicators': ['__nuxt', '_nuxt', 'nuxt-link']
            },
            'lodash': {
                'patterns': [
                    r'lodash[.-]([0-9.]+)(?:\.min)?\.js',
                    r'lodash\.VERSION\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['lodash.js', '_.']
            },
            'moment': {
                'patterns': [
                    r'moment[.-]([0-9.]+)(?:\.min)?\.js',
                    r'moment\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['moment.js', 'moment-with-locales']
            },
            'socket.io': {
                'patterns': [
                    r'socket\.io[.-]([0-9.]+)(?:\.min)?\.js',
                    r'io\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['socket.io.js', 'io.connect']
            },
            'd3': {
                'patterns': [
                    r'd3[.-]([0-9.]+)(?:\.min)?\.js',
                    r'd3\.version\s*=\s*[\'"]([0-9.]+)[\'"]'
                ],
                'indicators': ['d3.js', 'd3-']
            },
            'bootstrap': {
                'patterns': [
                    r'bootstrap[.-]([0-9.]+)(?:\.min)?\.js',
                    r'bootstrap/([0-9.]+)/',
                    r'"bootstrap":\s*"([0-9.]+)"'
                ],
                'indicators': ['bootstrap', 'navbar-toggler', 'container-fluid']
            }
        }

        # Detect frameworks and their versions
        for framework, data in framework_patterns.items():
            # First try to find version using patterns
            version_found = False
            for pattern in data['patterns']:
                matches = re.findall(pattern, content_str, re.IGNORECASE)
                if matches:
                    self.frameworks[framework] = matches[0]
                    version_found = True
                    break

            # If no version found but indicators present, mark as detected
            if not version_found and any(indicator in content_str or indicator in headers_str 
                                     for indicator in data['indicators']):
                self.frameworks[framework] = 'version unknown'
            # If no version found but indicators present, mark as detected
            if not version_found and any(indicator in content_str or indicator in headers_str 
                                       for indicator in data['indicators']):
                self.frameworks[framework] = 'version unknown'

        # Add check for build tools and bundlers
        build_tools = {
            'webpack': r'(?:webpack|__webpack_require__)',
            'vite': r'(?:/@vite/client|vite\.config)',
            'parcel': r'parcel-bundler',
            'rollup': r'rollup\.config',
            'babel': r'(?:babel-runtime|@babel/)',
            'typescript': r'(?:\.ts\b|tsconfig\.json)'
        }

        for tool, pattern in build_tools.items():
            if re.search(pattern, content_str, re.IGNORECASE):
                self.frameworks[f"{tool} (build tool)"] = 'detected'

        # Check for additional libraries that aren't in main patterns
        other_libs = {
            'axios': r'axios(?:\.min)?\.js',
            'three.js': r'three(?:\.min)?\.js',
            'chart.js': r'chart\.js(?:\.min)?'
        }
        
        for lib, pattern in other_libs.items():
            if re.search(pattern, content_str, re.IGNORECASE):
                self.frameworks[lib] = 'detected'
    
    def _detect_main_functions(self, content, source_url=None):
        """Detect main application functions and their usage patterns"""
        try:
            # Core application function patterns
            main_function_patterns = {
                'authentication': [
                    r'function\s+(login|signin|authenticate|auth)\s*\(',
                    r'(login|signin|authenticate|auth)\s*[:=]\s*(?:function|async)',
                    r'const\s+(login|signin|authenticate|auth)\s*='
                ],
                'data_fetching': [
                    r'function\s+(fetch|get|load|retrieve)Data\s*\(',
                    r'(fetchData|getData|loadData|retrieveData)\s*[:=]\s*(?:function|async)',
                    r'async\s+function\s+(fetch|get|load)\w*\s*\('
                ],
                'form_handling': [
                    r'function\s+(submit|validate|handle)Form\s*\(',
                    r'(submitForm|validateForm|handleForm|handleSubmit)\s*[:=]',
                    r'on(Submit|Change|Input|Blur)\s*[:=]'
                ],
                'state_management': [
                    r'(useState|useReducer|useContext|createStore|dispatch)\s*\(',
                    r'function\s+(reducer|store|state)\w*\s*\(',
                    r'(setState|updateState|getState)\s*\('
                ],
                'api_calls': [
                    r'(axios|fetch)\s*\.\s*(get|post|put|delete|patch)\s*\(',
                    r'function\s+(api|request|call)\w*\s*\(',
                    r'(apiCall|makeRequest|httpRequest)\s*[:=]'
                ],
                'routing': [
                    r'(useRouter|useNavigate|useHistory|Router)\s*\(',
                    r'function\s+(navigate|redirect|route)\w*\s*\(',
                    r'(push|replace|navigate)\s*\(\s*[\'"`]'
                ],
                'validation': [
                    r'function\s+(validate|check|verify)\w*\s*\(',
                    r'(isValid|validate|checkValid)\s*[:=]\s*(?:function|async)',
                    r'(email|phone|password)Validation\s*[:=]'
                ],
                'encryption_decryption': [
                    r'function\s+(encrypt|decrypt|hash|encode|decode)\w*\s*\(',
                    r'(encrypt|decrypt|hash|encode|decode)\s*[:=]\s*(?:function|async)',
                    r'(AES|RSA|SHA|MD5)\.(?:encrypt|decrypt)'
                ]
            }
            
            for category, patterns in main_function_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        if category not in self.main_functions:
                            self.main_functions[category] = []
                        for match in matches:
                            # Extract function name from tuple or string
                            func_name = match if isinstance(match, str) else (match[0] if match[0] else match[1] if len(match) > 1 else str(match))
                            if func_name:
                                # Store as dict with name and source
                                func_entry = {'name': func_name, 'source': source_url or 'inline'}
                                # Avoid duplicates
                                if not any(f['name'] == func_name and f['source'] == (source_url or 'inline') for f in self.main_functions[category]):
                                    self.main_functions[category].append(func_entry)
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Error detecting main functions: {e}")
    
    def _detect_crypto_logic(self, content, source_url=None):
        """Detect encryption and cryptographic implementations with exact algorithm details"""
        try:
            crypto_patterns = {
                'AES Encryption': [
                    (r'AES\.encrypt\s*\(', 'AES.encrypt() - CryptoJS'),
                    (r'crypto-js.*AES', 'CryptoJS AES'),
                    (r'CryptoJS\.AES\.(?:encrypt|decrypt)', 'CryptoJS AES'),
                    (r'aes-256-(?:cbc|gcm|ctr|ofb|cfb)', 'AES-256'),
                    (r'aes-192-(?:cbc|gcm|ctr|ofb|cfb)', 'AES-192'),
                    (r'aes-128-(?:cbc|gcm|ctr|ofb|cfb)', 'AES-128'),
                    (r'new\s+(?:AES|AESCipher)\s*\(', 'AES Cipher'),
                    (r'createCipheriv\s*\(\s*[\'"]aes-(\d+)-(\w+)', 'AES Cipher')
                ],
                'RSA Encryption': [
                    (r'RSA\.encrypt\s*\(', 'RSA.encrypt()'),
                    (r'new\s+RSA\s*\(', 'RSA Cipher'),
                    (r'new\s+JSEncrypt\s*\(', 'JSEncrypt RSA'),
                    (r'rsa-(\d+)', 'RSA Key Size'),
                    (r'publicKey.*BEGIN\s+(?:PUBLIC|RSA\s+PUBLIC)\s+KEY', 'RSA Public Key'),
                    (r'generateKeyPair\s*\(\s*[\'"]rsa[\'"]', 'RSA Key Generation'),
                    (r'RSAES-(?:PKCS1-v1_5|OAEP)', 'RSA Padding Scheme')
                ],
                'Hash Functions': [
                    (r'SHA1\s*\(', 'SHA-1 (Insecure!)'),
                    (r'MD5\s*\(', 'MD5 (Insecure!)'),
                    (r'SHA-?256', 'SHA-256'),
                    (r'SHA-?384', 'SHA-384'),
                    (r'SHA-?512', 'SHA-512'),
                    (r'crypto\.createHash\s*\(\s*[\'"](\w+)[\'"]', 'Node Crypto Hash'),
                    (r'CryptoJS\.(SHA1|MD5|SHA256|SHA384|SHA512)', 'CryptoJS Hash'),
                    (r'bcrypt\.hash', 'BCrypt Password Hash'),
                    (r'pbkdf2(?:Sync)?\s*\(', 'PBKDF2 Key Derivation'),
                    (r'scrypt\s*\(', 'Scrypt Key Derivation'),
                    (r'argon2', 'Argon2 Password Hash')
                ],
                'Base64 Encoding': [
                    (r'atob\s*\(', 'Base64 Decode (atob)'),
                    (r'btoa\s*\(', 'Base64 Encode (btoa)'),
                    (r'Buffer\.from\s*\(.*?[\'"]base64[\'"]', 'Node Buffer Base64'),
                    (r'toString\s*\(\s*[\'"]base64[\'"]', 'Base64 String Conversion'),
                    (r'base64\.(?:encode|decode)', 'Base64 Library')
                ],
                'JWT Tokens': [
                    (r'jwt\.sign\s*\(', 'JWT Signing'),
                    (r'jwt\.verify\s*\(', 'JWT Verification'),
                    (r'jwt\.decode\s*\(', 'JWT Decoding'),
                    (r'jsonwebtoken', 'JSON Web Token Library'),
                    (r'eyJ[A-Za-z0-9-_]{20,}\.eyJ[A-Za-z0-9-_]{20,}', 'Hardcoded JWT Token (CRITICAL!)'),
                    (r'Bearer\s+[A-Za-z0-9\-._~+/]{20,}', 'Bearer Token')
                ],
                'WebCrypto API': [
                    (r'crypto\.subtle\.encrypt', 'Web Crypto Encrypt'),
                    (r'crypto\.subtle\.decrypt', 'Web Crypto Decrypt'),
                    (r'crypto\.subtle\.sign', 'Web Crypto Sign'),
                    (r'crypto\.subtle\.verify', 'Web Crypto Verify'),
                    (r'crypto\.subtle\.digest', 'Web Crypto Digest'),
                    (r'crypto\.subtle\.generateKey', 'Web Crypto Key Generation'),
                    (r'window\.crypto\.getRandomValues', 'Crypto Random Values'),
                    (r'SubtleCrypto\.', 'SubtleCrypto API')
                ],
                'Custom Encryption': [
                    (r'function\s+(?:encrypt|decrypt|cipher|decipher)\s*\(', 'Custom Crypto Function'),
                    (r'(?:xor|rot13|caesar)(?:Encrypt|Cipher)', 'Weak Custom Cipher'),
                    (r'function\s+(?:scramble|unscramble|obfuscate)\s*\(', 'Obfuscation Function')
                ]
            }
            
            for crypto_type, patterns in crypto_patterns.items():
                for pattern_info in patterns:
                    # Handle tuple format (pattern, description)
                    if isinstance(pattern_info, tuple):
                        pattern, description = pattern_info
                    else:
                        pattern = pattern_info
                        description = pattern_info
                    
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        # Extract context around the match
                        for match in matches[:3]:  # Limit to first 3 matches per pattern
                            # Find the line containing the match
                            lines = content.split('\n')
                            for i, line in enumerate(lines):
                                # Get matched text
                                match_str = match if isinstance(match, str) else (match[0] if isinstance(match, tuple) and match else str(match))
                                if match_str and (match_str in line or re.search(pattern, line, re.IGNORECASE)):
                                    context = line.strip()[:200]  # First 200 chars
                                    self.crypto_implementations.append({
                                        'type': crypto_type,
                                        'algorithm': description,
                                        'pattern': match_str,
                                        'context': context,
                                        'source': source_url or 'inline'
                                    })
                                    break
                        break  # Only record once per crypto type
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Error detecting crypto: {e}")
    
    def _ai_analyze_javascript(self, content_sample, source_url=None):
        """Use AI to analyze JavaScript for security issues and patterns"""
        try:
            # Only run if Ollama is available and we have significant content
            if not hasattr(args, 'ollama_available') or not args.ollama_available:
                return
            
            if len(content_sample) < 500:  # Skip very small samples
                return
            
            # Truncate content to avoid overwhelming the AI
            analysis_content = content_sample[:3000]
            
            prompt = f"""Analyze this JavaScript code snippet for security concerns and patterns:

{analysis_content}

Provide a brief security analysis covering:
1. Potential security vulnerabilities (XSS, injection, hardcoded secrets)
2. Authentication/authorization patterns
3. Data handling practices  
4. Third-party dependencies or libraries used
5. Any suspicious or unusual patterns

Be concise and focus on actionable security insights. Format as bullet points."""

            print(f"{Fore.CYAN}[AI-ANALYSIS]{Style.RESET_ALL} Analyzing JavaScript code with AI...")
            
            # Query Ollama
            try:
                data = {
                    "model": "llama2",
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # Lower temperature for more focused analysis
                        "top_p": 0.9,
                        "num_predict": 500  # Limit response length
                    }
                }
                response = requests.post("http://localhost:11434/api/generate", 
                                       json=data, timeout=45)
                if response.status_code == 200:
                    result = response.json()
                    ai_response = result.get("response", "").strip()
                    if ai_response and len(ai_response) > 50:
                        self.ai_insights.append({
                            'analysis': ai_response,
                            'source': source_url or 'inline'
                        })
                        if args.verbose:
                            print(f"{Fore.GREEN}[AI-ANALYSIS]{Style.RESET_ALL} AI analysis completed")
            except Exception as e:
                if args.verbose:
                    print(f"{Fore.YELLOW}[AI-ANALYSIS]{Style.RESET_ALL} AI query failed: {e}")
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Error in AI analysis: {e}")
    
    def _detect_runtime_signatures(self, content):
        """Detect library versions from runtime code signatures in minified/bundled code"""
        versions = {}
        
        try:
            # React version detection from bundle structure
            if 'createElement' in content and '__REACT' in content:
                if 'createRoot' in content or '_createRoot' in content:
                    versions['React'] = '18.x'  # React 18+ has createRoot
                elif 'useTransition' in content or 'useDeferredValue' in content:
                    versions['React'] = '18.0-18.2'
                elif 'useId' in content:
                    versions['React'] = '18.0+'
                elif 'useSyncExternalStore' in content:
                    versions['React'] = '18.0+'
                elif 'useInsertionEffect' in content:
                    versions['React'] = '18.0+'
                elif '__SECRET_INTERNALS_DO_NOT_USE' in content and 'Suspense' in content:
                    versions['React'] = '16.8-17.x'
                elif 'useState' in content or 'useEffect' in content:
                    versions['React'] = '16.8+'  # Hooks introduced in 16.8
                else:
                    versions['React'] = '16.0-16.7'
                    
            # jQuery detection from method patterns
            if 'jquery' in content.lower() or ('$' in content and '.fn.jquery' in content):
                if '.prop(' in content and '.on(' in content:
                    if '.uniqueSort' in content:
                        versions['jQuery'] = '3.x'
                    elif '.andSelf' not in content:
                        versions['jQuery'] = '1.9-2.x'
                    else:
                        versions['jQuery'] = '1.x'
                        
            # Angular detection
            if 'angular' in content.lower():
                if '@angular/core' in content or 'platformBrowserDynamic' in content:
                    if 'standalone' in content:
                        versions['Angular'] = '14+'
                    elif 'inject(' in content:
                        versions['Angular'] = '2-13.x'
                    else:
                        versions['Angular'] = '2.x-13.x'
                elif 'ng-' in content or 'angular.module' in content:
                    versions['Angular'] = '1.x (AngularJS)'
                    
            # Lodash detection
            if 'lodash' in content.lower() or ('_.' in content and '_.VERSION' in content):
                if '_.cloneDeepWith' in content:
                    versions['Lodash'] = '4.17.0+'
                elif '_.flow' in content or '_.flowRight' in content:
                    versions['Lodash'] = '3.x-4.x'
                else:
                    versions['Lodash'] = '2.x-3.x'
                    
            # Moment.js detection
            if 'moment' in content.lower():
                if 'moment.locale' in content:
                    versions['Moment.js'] = '2.8.0+'
                else:
                    versions['Moment.js'] = '1.x-2.7.x'
                    
            # Bootstrap detection  
            if 'bootstrap' in content.lower():
                if '.modal(' in content:
                    if '.popover(' in content and '.tooltip(' in content:
                        if 'data-bs-' in content:
                            versions['Bootstrap'] = '5.x'
                        else:
                            versions['Bootstrap'] = '4.x'
                    else:
                        versions['Bootstrap'] = '3.x'
                        
            # axios detection
            if 'axios' in content.lower():
                if 'axios.create' in content:
                    if 'validateStatus' in content:
                        versions['axios'] = '0.19.0+'
                    else:
                        versions['axios'] = '0.x'
                        
            # Next.js detection
            if '_next' in content or '__NEXT' in content:
                if '__NEXT_DATA__' in content:
                    # Try to extract buildId which indicates Next version era
                    if 'app-index' in content or '_app-' in content:
                        versions['Next.js'] = '13.x+ (App Router)'
                    elif 'webpack' in content:
                        versions['Next.js'] = '9.x-12.x'
                    else:
                        versions['Next.js'] = '8.x or earlier'
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Runtime signature detection error: {e}")
                
        return versions
    
    def _detect_vulnerable_libraries(self, content, source_url=None):
        """Detect outdated and vulnerable JavaScript libraries with enhanced version detection"""
        try:
            # Known vulnerable library patterns with multiple version detection methods
            vulnerable_patterns = {
                'jQuery': {
                    'patterns': [
                        r'jquery[/-](\d+\.\d+(?:\.\d+)?)',
                        r'jQuery\s+v(\d+\.\d+(?:\.\d+)?)',
                        r'jquery.*?(\d+\.\d+\.\d+)',
                        r'\*\s+jQuery\s+v?(\d+\.\d+(?:\.\d+)?)',
                        r'version["\']?\s*:\s*["\'](\d+\.\d+(?:\.\d+)?)["\'].*jquery'
                    ],
                    'vulnerable_versions': {
                        '1.x': 'CVE-2020-11023 (XSS), CVE-2020-11022 (XSS)',
                        '2.x': 'CVE-2020-11023 (XSS), CVE-2020-11022 (XSS)',
                        '3.0-3.4': 'CVE-2020-11023 (XSS), CVE-2020-11022 (XSS)',
                        '3.5-3.6': 'CVE-2020-11023 (XSS)'
                    },
                    'safe_version': '3.7.0+'
                },
                'Angular': {
                    'patterns': [
                        r'angular(?:\.min)?\.js[/@](\d+\.\d+(?:\.\d+)?)',
                        r'@angular/core["\']?\s*:\s*["\'][\^~]?(\d+\.\d+(?:\.\d+)?)',
                        r'Angular\s+v?(\d+\.\d+(?:\.\d+)?)',
                        r'ng-version["\']?\s*:\s*["\'](\d+\.\d+(?:\.\d+)?)'
                    ],
                    'vulnerable_versions': {
                        '1.x': 'CVE-2023-26117 (XSS), CVE-2023-26116 (ReDoS)',
                        '1.0-1.7': 'Multiple XSS vulnerabilities'
                    },
                    'safe_version': '1.8.0+ or migrate to Angular 2+'
                },
                'React': {
                    'patterns': [
                        r'react(?:\.min)?\.js[/@](\d+\.\d+(?:\.\d+)?)',
                        r'React\s+v?(\d+\.\d+(?:\.\d+)?)',
                        r'["\']react["\']:\s*["\'][\^~]?(\d+\.\d+(?:\.\d+)?)',
                        r'__REACT_DEVTOOLS_GLOBAL_HOOK__.*?(\d+\.\d+\.\d+)'
                    ],
                    'vulnerable_versions': {
                        '16.0-16.13': 'CVE-2020-15168 (Information Disclosure)',
                        '17.0-17.0.1': 'CVE-2021-23436'
                    },
                    'safe_version': '18.0.0+'
                },
                'Lodash': {
                    'patterns': [
                        r'lodash(?:\.min)?\.js[/@](\d+\.\d+(?:\.\d+)?)',
                        r'["\']lodash["\']:\s*["\'][\^~]?(\d+\.\d+(?:\.\d+)?)',
                        r'Lodash\s+v?(\d+\.\d+(?:\.\d+)?)',
                        r'_\.VERSION\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)'
                    ],
                    'vulnerable_versions': {
                        '4.0-4.17.20': 'CVE-2021-23337 (Command Injection), CVE-2020-28500 (ReDoS)',
                        '4.17.0-4.17.15': 'CVE-2019-10744 (Prototype Pollution)'
                    },
                    'safe_version': '4.17.21+'
                },
                'Moment.js': {
                    'patterns': [
                        r'moment(?:\.min)?\.js[/@](\d+\.\d+(?:\.\d+)?)',
                        r'["\']moment["\']:\s*["\'][\^~]?(\d+\.\d+(?:\.\d+)?)',
                        r'moment\.version\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)'
                    ],
                    'vulnerable_versions': {
                        '2.0-2.29.3': 'CVE-2022-24785 (Path Traversal), CVE-2022-31129 (ReDoS)',
                        'all': 'DEPRECATED - Use date-fns or dayjs'
                    },
                    'safe_version': 'Migrate to date-fns or dayjs'
                },
                'Bootstrap': {
                    'patterns': [
                        r'bootstrap(?:\.min)?\.js[/@](\d+\.\d+(?:\.\d+)?)',
                        r'Bootstrap\s+v?(\d+\.\d+(?:\.\d+)?)',
                        r'["\']bootstrap["\']:\s*["\'][\^~]?(\d+\.\d+(?:\.\d+)?)'
                    ],
                    'vulnerable_versions': {
                        '3.x': 'CVE-2019-8331 (XSS), CVE-2018-14042 (XSS)',
                        '4.0-4.6.0': 'CVE-2019-8331 (XSS)'
                    },
                    'safe_version': '5.0.0+'
                },
                'axios': {
                    'patterns': [
                        r'axios[/@](\d+\.\d+(?:\.\d+)?)',
                        r'["\']axios["\']:\s*["\'][\^~]?(\d+\.\d+(?:\.\d+)?)',
                        r'axios\.VERSION\s*=\s*["\'](\d+\.\d+(?:\.\d+)?)'
                    ],
                    'vulnerable_versions': {
                        '0.x-1.5.1': 'CVE-2023-45857 (CSRF), CVE-2024-39338'
                    },
                    'safe_version': '1.6.0+'
                },
                'Next.js': {
                    'patterns': [
                        r'next[/@](\d+\.\d+(?:\.\d+)?)',
                        r'["\']next["\']:\s*["\'][\^~]?(\d+\.\d+(?:\.\d+)?)',
                        r'__NEXT_DATA__.*?buildId["\']?\s*:\s*["\']([^"\']+)'
                    ],
                    'vulnerable_versions': {},
                    'safe_version': 'Latest stable'
                }
            }
            
            content_lower = content.lower()
            
            # Additional runtime signature detection for minified code
            runtime_signatures = self._detect_runtime_signatures(content)
            
            for lib_name, lib_info in vulnerable_patterns.items():
                detected_version = None
                
                # Try runtime signature detection first (works on minified code)
                if lib_name in runtime_signatures:
                    detected_version = runtime_signatures[lib_name]
                    self.library_versions[lib_name] = detected_version
                    if args.verbose:
                        print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Detected {lib_name} {detected_version} via runtime signatures")
                
                # If not found via signatures, try regex patterns
                if not detected_version:
                    for pattern in lib_info['patterns']:
                        version_match = re.search(pattern, content, re.IGNORECASE)
                        if version_match:
                            detected_version = version_match.group(1)
                            self.library_versions[lib_name] = detected_version
                            if args.verbose:
                                print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Detected {lib_name} {detected_version} via regex pattern")
                            break
                
                if detected_version:
                    # Check if version is vulnerable
                    is_vulnerable = False
                    vulnerabilities = []
                    
                    for vuln_range, cves in lib_info['vulnerable_versions'].items():
                        if vuln_range == 'all' or self._version_in_range(detected_version, vuln_range):
                            is_vulnerable = True
                            vulnerabilities.append(cves)
                    
                    if is_vulnerable:
                        self.vulnerable_libs.append({
                            'library': lib_name,
                            'version': detected_version,
                            'vulnerabilities': vulnerabilities,
                            'safe_version': lib_info['safe_version'],
                            'source': source_url or 'inline'
                        })
                elif lib_name.lower() in content_lower:
                    # Library detected but version unknown - only add if not already in versions dict
                    if lib_name not in self.library_versions:
                        self.library_versions[lib_name] = 'unknown'
                        if lib_info['vulnerable_versions']:  # Only flag if it has known vulnerabilities
                            self.vulnerable_libs.append({
                                'library': lib_name,
                                'version': 'unknown',
                                'vulnerabilities': ['Version not detected - manual review recommended'],
                                'safe_version': lib_info['safe_version'],
                                'source': source_url or 'inline'
                            })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Error detecting vulnerable libraries: {e}")
    
    def _update_vulnerable_libs_with_detected_versions(self):
        """Update vulnerable_libs list with actually detected versions from library_versions dict"""
        try:
            # Build a new list with updated versions and re-check vulnerability status
            updated_libs = []
            seen_libraries = set()
            
            # Get vulnerable patterns for re-checking
            vulnerable_patterns = {
                'jQuery': {'vulnerable_versions': {'1.x': 'XSS', '2.x': 'XSS', '3.0-3.4': 'XSS', '3.5-3.6': 'XSS'}},
                'React': {'vulnerable_versions': {'16.0-16.13': 'CVE-2020-15168', '17.0-17.0.1': 'CVE-2021-23436'}},
                'Moment.js': {'vulnerable_versions': {'2.0-2.29.3': 'CVE-2022-24785', 'all': 'DEPRECATED'}},
                'Angular': {'vulnerable_versions': {'1.x': 'XSS', '1.0-1.7': 'XSS'}},
                'Lodash': {'vulnerable_versions': {'4.0-4.17.20': 'CVE-2021-23337'}},
                'Bootstrap': {'vulnerable_versions': {'3.x': 'CVE-2019-8331', '4.0-4.6.0': 'CVE-2019-8331'}},
                'axios': {'vulnerable_versions': {'0.x-1.5.1': 'CVE-2023-45857'}}
            }
            
            for vuln in self.vulnerable_libs:
                lib_name = vuln['library']
                
                # Skip if we already processed this library
                if lib_name in seen_libraries:
                    continue
                seen_libraries.add(lib_name)
                
                # Check if we have a better version detection
                if lib_name in self.library_versions:
                    detected_version = self.library_versions[lib_name]
                    
                    # Only update if we found an actual version (not "unknown")
                    if detected_version and detected_version != 'unknown':
                        vuln['version'] = detected_version
                        
                        # Re-check if this version is actually vulnerable
                        if lib_name in vulnerable_patterns:
                            is_vulnerable = False
                            vuln_list = []
                            
                            for vuln_range, cve in vulnerable_patterns[lib_name]['vulnerable_versions'].items():
                                if vuln_range == 'all' or self._version_in_range(detected_version, vuln_range):
                                    is_vulnerable = True
                                    vuln_list.append(cve)
                            
                            # If not vulnerable with detected version, skip adding to list
                            if not is_vulnerable:
                                if args.verbose:
                                    print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} {lib_name} {detected_version} is NOT vulnerable - removed from list")
                                continue
                            else:
                                vuln['vulnerabilities'] = vuln_list
                        
                        if args.verbose:
                            print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Updated {lib_name} version to {detected_version}")
                
                updated_libs.append(vuln)
            
            # Replace the list
            self.vulnerable_libs = updated_libs
            
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Error updating vulnerable libs: {e}")
    
    def _version_in_range(self, version, vuln_range):
        """Check if a version falls within a vulnerable range"""
        try:
            # Parse version numbers
            version_parts = [int(x) for x in version.split('.')]
            
            # Handle range formats like "1.x", "4.0-4.17.20", "16.0-16.13"
            if '.x' in vuln_range or 'x' == vuln_range[-1]:
                # Match major version
                major = int(vuln_range.split('.')[0])
                return version_parts[0] == major
            elif '-' in vuln_range:
                # Range check
                start, end = vuln_range.split('-')
                start_parts = [int(x) for x in start.split('.')]
                end_parts = [int(x) for x in end.split('.')]
                return start_parts <= version_parts <= end_parts
            else:
                # Exact match
                return version == vuln_range
        except:
            return False
    
    def _display_findings(self):
        """Display all findings in an organized manner"""
        
        # NEW: Main Functions Detection
        if self.main_functions:
            print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[MAIN APPLICATION FUNCTIONS]{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            for category, functions in sorted(self.main_functions.items()):
                if functions:
                    print(f"\n{Fore.CYAN}[{category.upper().replace('_', ' ')}]{Style.RESET_ALL}")
                    for func in sorted(functions, key=lambda x: x['name'] if isinstance(x, dict) else x):
                        if isinstance(func, dict):
                            print(f"  {Fore.YELLOW}►{Style.RESET_ALL} {func['name']}")
                            print(f"    {Fore.CYAN}Source:{Style.RESET_ALL} {func['source']}")
                        else:
                            # Backward compatibility for old set-based entries
                            print(f"  {Fore.YELLOW}►{Style.RESET_ALL} {func}")
        
        # NEW: Cryptographic Implementations
        if self.crypto_implementations:
            print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[ENCRYPTION & CRYPTOGRAPHIC LOGIC]{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            
            # Group by type
            crypto_by_type = {}
            for crypto in self.crypto_implementations:
                crypto_type = crypto['type']
                if crypto_type not in crypto_by_type:
                    crypto_by_type[crypto_type] = []
                crypto_by_type[crypto_type].append(crypto)
            
            for crypto_type, implementations in sorted(crypto_by_type.items()):
                print(f"\n{Fore.CYAN}[{crypto_type.upper()}]{Style.RESET_ALL}")
                for impl in implementations[:3]:  # Show first 3 of each type
                    print(f"  {Fore.YELLOW}Algorithm:{Style.RESET_ALL} {impl.get('algorithm', impl['pattern'])}")
                    print(f"  {Fore.YELLOW}Pattern:{Style.RESET_ALL} {impl['pattern'][:80]}")
                    print(f"  {Fore.YELLOW}Context:{Style.RESET_ALL} {impl['context'][:150]}")
                    if 'source' in impl:
                        print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {impl['source']}")
                    print()
        
        # NEW: Vulnerable Libraries
        if self.vulnerable_libs:
            print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.RED}[⚠ VULNERABLE & OUTDATED LIBRARIES DETECTED ⚠]{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
            
            for vuln in self.vulnerable_libs:
                print(f"\n{Fore.RED}[CRITICAL]{Style.RESET_ALL} {Fore.YELLOW}{vuln['library']}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Detected Version:{Style.RESET_ALL} {vuln['version']}")
                if 'source' in vuln:
                    print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {vuln['source']}")
                print(f"  {Fore.RED}Vulnerabilities:{Style.RESET_ALL}")
                for v in vuln['vulnerabilities']:
                    print(f"    {Fore.YELLOW}►{Style.RESET_ALL} {v}")
                print(f"  {Fore.GREEN}Recommended:{Style.RESET_ALL} Upgrade to {vuln['safe_version']}")
        
        # NEW: AI Security Insights
        if self.ai_insights:
            print(f"\n{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}[🤖 AI SECURITY ANALYSIS]{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
            
            for idx, insight in enumerate(self.ai_insights, 1):
                print(f"\n{Fore.CYAN}[Analysis #{idx}]{Style.RESET_ALL}")
                if isinstance(insight, dict):
                    if 'source' in insight:
                        print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {insight['source']}")
                    # Format AI output with proper indentation
                    analysis_text = insight.get('analysis', insight)
                    for line in str(analysis_text).split('\n'):
                        if line.strip():
                            print(f"  {line}")
                else:
                    # Backward compatibility for old string-based insights
                    for line in str(insight).split('\n'):
                        if line.strip():
                            print(f"  {line}")
        
        if self.frameworks:
            print(f"\n{Fore.GREEN}[FRAMEWORKS DETECTED]{Style.RESET_ALL}")
            for framework, version in self.frameworks.items():
                # Check if we have a better version from library_versions
                detected_version = version
                
                # Try to match framework name with library_versions (case-insensitive + partial match)
                framework_lower = framework.lower().replace(' (build tool)', '').replace('-', '').replace('.', '')
                for lib_name, lib_version in self.library_versions.items():
                    lib_lower = lib_name.lower().replace('-', '').replace('.', '')
                    # Check for exact match or if one contains the other
                    if lib_lower == framework_lower or lib_lower in framework_lower or framework_lower in lib_lower:
                        if lib_version and lib_version != 'unknown':
                            detected_version = lib_version
                            break
                
                # Color code based on version detection
                if detected_version and detected_version not in ['version unknown', 'detected', 'unknown']:
                    version_color = Fore.GREEN
                else:
                    version_color = Fore.YELLOW
                    
                print(f"{Fore.CYAN}[{framework.upper()}]{Style.RESET_ALL} Version: {version_color}{detected_version}{Style.RESET_ALL}")
        
        if self.js_files:
            print(f"\n{Fore.GREEN}[JAVASCRIPT FILES]{Style.RESET_ALL}")
            for js in sorted(self.js_files):
                print(f"{Fore.CYAN}[JS]{Style.RESET_ALL} {js}")
        
        if self.event_handlers:
            print(f"\n{Fore.GREEN}[EVENT HANDLERS]{Style.RESET_ALL}")
            for handler in sorted(self.event_handlers):
                print(f"{Fore.CYAN}[EVENT]{Style.RESET_ALL} {handler}")
        
        if self.discovered_endpoints:
            print(f"\n{Fore.GREEN}[ENDPOINTS DISCOVERED]{Style.RESET_ALL}")
            for endpoint in sorted(self.discovered_endpoints):
                print(f"{Fore.CYAN}[ENDPOINT]{Style.RESET_ALL} {endpoint}")
        
        if self.api_patterns:
            print(f"\n{Fore.GREEN}[API PATTERNS]{Style.RESET_ALL}")
            for pattern in sorted(self.api_patterns):
                print(f"{Fore.CYAN}[API]{Style.RESET_ALL} {pattern}")
        
        if self.ajax_calls:
            print(f"\n{Fore.GREEN}[AJAX CALLS]{Style.RESET_ALL}")
            for call in sorted(self.ajax_calls):
                print(f"{Fore.CYAN}[AJAX]{Style.RESET_ALL} {call}")
        
        if self.websockets:
            print(f"\n{Fore.GREEN}[WEBSOCKET ENDPOINTS]{Style.RESET_ALL}")
            for ws in sorted(self.websockets):
                print(f"{Fore.CYAN}[WS]{Style.RESET_ALL} {ws}")
        
        if self.secrets:
            print(f"\n{Fore.RED}[SENSITIVE INFORMATION]{Style.RESET_ALL}")
            
            # Group secrets by category
            secrets_by_category = {}
            for secret in self.secrets:
                if isinstance(secret, dict):
                    category = secret.get('category', 'Unknown')
                    if category not in secrets_by_category:
                        secrets_by_category[category] = []
                    secrets_by_category[category].append(secret)
                else:
                    # Backward compatibility for old string format
                    print(f"{Fore.RED}[SECRET]{Style.RESET_ALL} {secret}")
            
            # Display grouped by category
            for category in sorted(secrets_by_category.keys()):
                print(f"\n{Fore.YELLOW}[{category}]{Style.RESET_ALL}")
                for secret in secrets_by_category[category]:
                    print(f"  {Fore.RED}Value:{Style.RESET_ALL} {secret['value']}")
                    print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {secret['source']}")
        
        # ==================================================================================
        # ADVANCED SECURITY FINDINGS DISPLAY
        # ==================================================================================
        
        # Supply Chain Risks
        if self.supply_chain_risks:
            print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.RED}[⚠ SUPPLY CHAIN SECURITY RISKS ⚠]{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
            for risk in self.supply_chain_risks[:10]:  # Show first 10
                print(f"\n{Fore.RED}[{risk['severity']}]{Style.RESET_ALL} {risk['risk']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {risk['source']}")
                if 'matched_value' in risk:
                    print(f"  {Fore.YELLOW}Matched Value:{Style.RESET_ALL} {risk['matched_value'][:80]}")
                if 'context' in risk:
                    print(f"  {Fore.MAGENTA}Context:{Style.RESET_ALL} {risk['context'][:120]}")
                print(f"  {Fore.YELLOW}Pattern:{Style.RESET_ALL} {risk['pattern'][:100]}")
        
        if self.missing_sri:
            print(f"\n{Fore.YELLOW}[MISSING SRI HASHES]{Style.RESET_ALL}")
            for item in self.missing_sri[:5]:
                print(f"  {Fore.YELLOW}►{Style.RESET_ALL} {item['url']}")
                print(f"    {Fore.RED}Risk:{Style.RESET_ALL} {item['risk']}")
        
        if self.typosquatting_risks:
            print(f"\n{Fore.RED}[TYPOSQUATTING RISKS]{Style.RESET_ALL}")
            for risk in self.typosquatting_risks:
                print(f"  {Fore.RED}Suspected:{Style.RESET_ALL} {risk['suspected_typo']} → {Fore.GREEN}Legitimate:{Style.RESET_ALL} {risk['legitimate']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {risk['source']}")
        
        # XSS & Injection Vulnerabilities
        if self.dom_xss_sinks:
            print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.RED}[DOM-BASED XSS SINKS DETECTED]{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
            for sink in self.dom_xss_sinks[:15]:  # Show first 15
                print(f"\n{Fore.RED}[{sink['severity']}]{Style.RESET_ALL} {Fore.YELLOW}{sink['type']}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {sink['source']}")
                print(f"  {Fore.YELLOW}Context:{Style.RESET_ALL} {sink['context'][:150]}")
        
        if self.prototype_pollution:
            print(f"\n{Fore.RED}[PROTOTYPE POLLUTION VULNERABILITIES]{Style.RESET_ALL}")
            for vuln in self.prototype_pollution[:10]:
                print(f"\n{Fore.RED}[{vuln['severity']}]{Style.RESET_ALL} {vuln['pattern']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {vuln['source']}")
                print(f"  {Fore.YELLOW}Context:{Style.RESET_ALL} {vuln['context'][:150]}")
        
        if self.csti_vulns:
            print(f"\n{Fore.RED}[CLIENT-SIDE TEMPLATE INJECTION]{Style.RESET_ALL}")
            for vuln in self.csti_vulns[:10]:
                print(f"\n{Fore.RED}[HIGH]{Style.RESET_ALL} {vuln['type']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {vuln['source']}")
                print(f"  {Fore.YELLOW}Context:{Style.RESET_ALL} {vuln['context'][:150]}")
        
        # Advanced Secret Detection
        if self.high_entropy_secrets:
            print(f"\n{Fore.MAGENTA}[HIGH-ENTROPY SECRETS (Possible Tokens/Keys)]{Style.RESET_ALL}")
            for secret in self.high_entropy_secrets[:10]:
                print(f"\n  {Fore.YELLOW}Value:{Style.RESET_ALL} {secret['value']}")
                print(f"  {Fore.CYAN}Entropy:{Style.RESET_ALL} {secret['entropy']} | {Fore.CYAN}Length:{Style.RESET_ALL} {secret['length']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {secret['source']}")
        
        if self.private_keys:
            print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.RED}[CRITICAL: PRIVATE KEYS EXPOSED]{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
            for key in self.private_keys:
                print(f"\n{Fore.RED}[CRITICAL]{Style.RESET_ALL} {key['type']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {key['source']}")
                print(f"  {Fore.YELLOW}Preview:{Style.RESET_ALL} {key['context'][:100]}...")
        
        if self.source_maps:
            print(f"\n{Fore.RED}[SOURCE MAPS EXPOSED]{Style.RESET_ALL}")
            for smap in self.source_maps:
                print(f"\n{Fore.RED}[HIGH]{Style.RESET_ALL} Source Map Found")
                print(f"  {Fore.CYAN}URL:{Style.RESET_ALL} {smap['url']}")
                print(f"  {Fore.RED}Risk:{Style.RESET_ALL} {smap['risk']}")
        
        # API & Communication
        if self.graphql_endpoints:
            print(f"\n{Fore.CYAN}[GRAPHQL ENDPOINTS]{Style.RESET_ALL}")
            for endpoint in self.graphql_endpoints[:10]:
                print(f"\n  {Fore.YELLOW}Type:{Style.RESET_ALL} {endpoint['type']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {endpoint['source']}")
                print(f"  {Fore.YELLOW}Context:{Style.RESET_ALL} {endpoint['context'][:150]}")
        
        if self.postmessage_issues:
            print(f"\n{Fore.RED}[POSTMESSAGE SECURITY ISSUES]{Style.RESET_ALL}")
            for issue in self.postmessage_issues:
                severity = issue.get('severity', 'MEDIUM')
                print(f"\n{Fore.RED}[{severity}]{Style.RESET_ALL} {issue['type']}")
                print(f"  {Fore.CYAN}Origin Validation:{Style.RESET_ALL} {Fore.GREEN if issue['has_origin_validation'] else Fore.RED}{issue['has_origin_validation']}{Style.RESET_ALL}")
                print(f"  {Fore.RED}Risk:{Style.RESET_ALL} {issue['risk']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {issue['source']}")
        
        if self.ssrf_vectors:
            print(f"\n{Fore.YELLOW}[POTENTIAL SSRF VECTORS]{Style.RESET_ALL}")
            for vec in self.ssrf_vectors[:10]:
                print(f"\n  {Fore.YELLOW}Type:{Style.RESET_ALL} {vec['type']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {vec['source']}")
                print(f"  {Fore.YELLOW}Context:{Style.RESET_ALL} {vec['context'][:150]}")
        
        # Storage & Privacy
        if self.storage_exposure:
            print(f"\n{Fore.RED}[STORAGE SECURITY ISSUES]{Style.RESET_ALL}")
            for issue in self.storage_exposure[:10]:
                print(f"\n{Fore.RED}[{issue['severity']}]{Style.RESET_ALL} {issue['type']}")
                print(f"  {Fore.CYAN}Encrypted:{Style.RESET_ALL} {Fore.GREEN if issue['encrypted'] else Fore.RED}{issue['encrypted']}{Style.RESET_ALL}")
                print(f"  {Fore.RED}Risk:{Style.RESET_ALL} {issue['risk']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {issue['source']}")
        
        if self.fingerprinting:
            print(f"\n{Fore.YELLOW}[BROWSER FINGERPRINTING DETECTED]{Style.RESET_ALL}")
            techniques = {}
            for fp in self.fingerprinting:
                techniques[fp['technique']] = techniques.get(fp['technique'], 0) + 1
            for technique, count in techniques.items():
                print(f"  {Fore.YELLOW}►{Style.RESET_ALL} {technique} ({count} instances)")
        
        # Modern Web Tech
        if self.wasm_modules:
            print(f"\n{Fore.CYAN}[WEBASSEMBLY MODULES]{Style.RESET_ALL}")
            for wasm in self.wasm_modules[:5]:
                print(f"\n  {Fore.YELLOW}Type:{Style.RESET_ALL} {wasm['type']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {wasm['source']}")
        
        if self.service_workers:
            print(f"\n{Fore.CYAN}[SERVICE WORKERS]{Style.RESET_ALL}")
            for sw in self.service_workers[:5]:
                print(f"\n  {Fore.YELLOW}Type:{Style.RESET_ALL} {sw['type']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {sw['source']}")
        
        if self.webrtc_leaks:
            print(f"\n{Fore.YELLOW}[WEBRTC POTENTIAL IP LEAKS]{Style.RESET_ALL}")
            for leak in self.webrtc_leaks:
                print(f"\n  {Fore.YELLOW}Type:{Style.RESET_ALL} {leak['type']}")
                print(f"  {Fore.RED}Risk:{Style.RESET_ALL} {leak['risk']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {leak['source']}")
        
        # Code Analysis
        if self.obfuscated_code:
            print(f"\n{Fore.RED}[OBFUSCATED CODE DETECTED]{Style.RESET_ALL}")
            for obf in self.obfuscated_code:
                print(f"\n{Fore.RED}[{obf['severity']}]{Style.RESET_ALL} Obfuscation Score: {obf['score']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {obf['source']}")
                print(f"  {Fore.YELLOW}Patterns:{Style.RESET_ALL} {obf['patterns']}")
                print(f"  {Fore.RED}Risk:{Style.RESET_ALL} {obf['risk']}")
        
        if self.weak_crypto:
            print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.RED}[WEAK CRYPTOGRAPHIC IMPLEMENTATIONS]{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
            for crypto in self.weak_crypto[:10]:
                print(f"\n{Fore.RED}[{crypto['severity']}]{Style.RESET_ALL} {crypto['type']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {crypto['source']}")
                print(f"  {Fore.YELLOW}Context:{Style.RESET_ALL} {crypto['context'][:150]}")
        
        if self.clickjacking_vectors:
            print(f"\n{Fore.YELLOW}[CLICKJACKING ANALYSIS]{Style.RESET_ALL}")
            for vec in self.clickjacking_vectors[:5]:
                print(f"\n  {Fore.YELLOW}Type:{Style.RESET_ALL} {vec['type']}")
                print(f"  {Fore.CYAN}Frame Busting:{Style.RESET_ALL} {Fore.GREEN if vec['has_frame_busting'] else Fore.RED}{vec['has_frame_busting']}{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {vec['source']}")
        
        # NEW: CORS Misconfigurations
        if self.cors_issues:
            print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.RED}[CORS MISCONFIGURATIONS]{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
            for cors in self.cors_issues:
                severity_color = Fore.RED if cors['severity'] == 'CRITICAL' else Fore.YELLOW if cors['severity'] == 'HIGH' else Fore.CYAN
                print(f"\n{severity_color}[{cors['severity']}]{Style.RESET_ALL} {cors['type']}")
                print(f"  {Fore.CYAN}Tested Origin:{Style.RESET_ALL} {cors['origin_tested']}")
                print(f"  {Fore.CYAN}Method:{Style.RESET_ALL} {cors['method']}")
                print(f"  {Fore.CYAN}Source:{Style.RESET_ALL} {cors['source']}")
                print(f"  {Fore.YELLOW}Details:{Style.RESET_ALL} {cors['details']}")

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

    def _scan_sensitive_data(self, content, source_url=None):
        """Scan for sensitive information in JavaScript with enhanced detection"""
        sensitive_patterns = {
            'API Keys & Tokens': [
                r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{20,})[\'"`]',
                r'(?i)(?:api[_-]?token|apitoken)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{20,})[\'"`]',
                r'(?i)(?:access[_-]?token|accesstoken)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{20,})[\'"`]',
                r'(?i)(?:client[_-]?secret|clientsecret)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{20,})[\'"`]',
                r'(?i)(?:app[_-]?key|appkey)\s*[=:]\s*[\'"`]([A-Za-z0-9_\-]{20,})[\'"`]',
                r'[\'"`]([A-Za-z0-9_\-]{40,})[\'"`].*(?:key|token)',  # Long strings near key/token keywords
            ],
            'AWS Credentials': [
                r'(?i)AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)aws[_-]?session[_-]?token\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)s3[_-]?bucket\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)s3://[a-z0-9\-._]+',  # S3 Bucket URLs
            ],
            'Cloud Service Keys': [
                r'(?i)google[_-]?api[_-]?key\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)firebase[_-]?api[_-]?key\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)azure[_-]?(?:key|secret|token)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)gcp[_-]?(?:key|secret|token)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)cloudflare[_-]?api[_-]?key\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
            ],
            'Database Credentials': [
                r'(?i)(?:mongodb|mysql|postgresql|postgres|redis|mssql)[_-]?(?:url|uri|connection|string)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)database[_-]?(?:url|uri|connection|password)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)db[_-]?(?:password|pass|pwd|user|username)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'mongodb(?:\+srv)?://[^\s\'"`,]+',  # MongoDB connection string
                r'postgres(?:ql)?://[^\s\'"`,]+',  # PostgreSQL connection string
            ],
            'Authentication Credentials': [
                r'(?i)password\s*[=:]\s*[\'"`]([^\'"`,]{6,})[\'"`]',
                r'(?i)passwd\s*[=:]\s*[\'"`]([^\'"`,]{6,})[\'"`]',
                r'(?i)pwd\s*[=:]\s*[\'"`]([^\'"`,]{6,})[\'"`]',
                r'(?i)secret\s*[=:]\s*[\'"`]([^\'"`,]{8,})[\'"`]',
                r'(?i)auth[_-]?token\s*[=:]\s*[\'"`]([^\'"`,]{20,})[\'"`]',
                r'(?i)session[_-]?(?:id|token|key)\s*[=:]\s*[\'"`]([^\'"`,]{20,})[\'"`]',
            ],
            'JWT Tokens': [
                r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  # Full JWT
                r'(?i)bearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',  # Bearer JWT
            ],
            'Private Keys': [
                r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----',
                r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            ],
            'Email Addresses': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            'Phone Numbers': [
                r'(?i)(?:phone|mobile|tel|contact)[\'"]?\s*[=:]\s*[\'"`]?(\+?[0-9\s\-()]{10,})[\'"`]?',
                r'\+?[0-9]{1,3}[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            ],
            'IP Addresses (Internal)': [
                r'(?:http|https)://(?:localhost|127\.0\.0\.1|192\.168\.|10\.0\.|172\.16\.|internal\.|dev\.|staging\.|test\.)[^\s\'"`,]+',
                r'(?:http|https)://[^\s\'"`,]*\.(?:local|internal|dev|test|staging)[^\s\'"`,]*',
                r'\b(?:10|172|192)\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b',
            ],
            'Credit Card Numbers': [
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            ],
            'OAuth & Social Media': [
                r'(?i)(?:facebook|fb)[_-]?(?:app[_-]?)?(?:id|secret)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)(?:twitter|oauth)[_-]?(?:consumer[_-]?)?(?:key|secret)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)github[_-]?(?:token|key)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)slack[_-]?(?:webhook|token)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
            ],
            'Payment Gateway Keys': [
                r'(?i)stripe[_-]?(?:api[_-]?)?(?:key|secret|token)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)paypal[_-]?(?:client[_-]?)?(?:id|secret)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'(?i)razorpay[_-]?(?:key|secret)\s*[=:]\s*[\'"`]([^\'"`,]+)[\'"`]',
                r'pk_live_[0-9a-zA-Z]{24,}',  # Stripe publishable key
                r'sk_live_[0-9a-zA-Z]{24,}',  # Stripe secret key
            ]
        }

        for category, patterns in sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    # Get the actual matched value
                    if isinstance(match, tuple):
                        match_value = next((m for m in match if m), str(match))
                    else:
                        match_value = match
                    
                    # Skip common false positives
                    false_positives = ['example', 'test', 'demo', 'placeholder', 'your-', 'xxx', '***', 
                                     'lorem', 'ipsum', 'dummy', 'sample', '12345', 'null', 'undefined',
                                     'XXXXXXXX', 'xxxxxxxxx', 'abcdef', '000000']
                    
                    if any(fp in str(match_value).lower() for fp in false_positives):
                        continue
                    
                    # Additional validation for specific categories
                    if category == 'Phone Numbers':
                        # Filter out common false positives for phone numbers
                        phone_str = str(match_value).replace('-', '').replace(' ', '').replace('(', '').replace(')', '').replace('.', '')
                        
                        # Skip if it's a credit card test number or sequential/repeated digits
                        if len(phone_str) > 10:
                            # Check for repeated digits (e.g., 666666666658)
                            if len(set(phone_str[:6])) == 1:  # First 6 digits are same
                                continue
                            # Check for test credit card patterns (like 5413256...)
                            if phone_str.startswith(('5413', '5030', '3021', '0204', '0205', '0206')):
                                continue
                            # Check if it's mostly zeros or sequential
                            if phone_str.count('0') > len(phone_str) * 0.5:
                                continue
                            # Skip numbers that look like product IDs or order numbers
                            if len(phone_str) > 12:  # Too long for phone
                                continue
                        
                    if category == 'Credit Card Numbers':
                        # Additional validation for credit cards (Luhn algorithm could be added)
                        # For now, skip obvious test cards
                        card_str = str(match_value).replace(' ', '').replace('-', '')
                        test_cards = [
                            '4111111111111111',  # Visa test
                            '5555555555554444',  # Mastercard test
                            '378282246310005',   # Amex test
                        ]
                        if any(test in card_str for test in test_cards):
                            continue
                    
                    # Truncate very long matches for display
                    display_value = str(match_value)[:100] + ('...' if len(str(match_value)) > 100 else '')
                    
                    # Add as dict with category, value, and source
                    secret_entry = {
                        'category': category,
                        'value': display_value,
                        'source': source_url or 'inline'
                    }
                    # Avoid duplicates
                    if not any(s['category'] == category and s['value'] == display_value and s['source'] == (source_url or 'inline') for s in self.secrets):
                        self.secrets.append(secret_entry)

    # ==================================================================================
    # ADVANCED DETECTION METHODS - 20 Modern Attack Vector Analysis
    # ==================================================================================
    
    def _check_supply_chain_risks(self, script_url, content):
        """Detect supply chain attacks and compromised dependencies"""
        try:
            # Check for missing SRI (Subresource Integrity)
            if 'cdn' in script_url.lower() or 'cloudflare' in script_url.lower() or 'cloudfront' in script_url.lower():
                self.missing_sri.append({
                    'url': script_url,
                    'risk': 'CDN resource without SRI hash - vulnerable to tampering',
                    'recommendation': 'Add integrity="" attribute with hash'
                })
            
            # Detect known malicious patterns
            malicious_patterns = [
                (r'eval\s*\(\s*atob\s*\(', 'Base64 encoded eval - common malware pattern', False),
                (r'document\.write\s*\(\s*unescape', 'Unescape with document.write - potential malware', False),
                (r'(?:btc|bitcoin|ethereum|eth).*?address', 'Cryptocurrency references - potential crypto miner', False),
                (r'(?:0x[a-fA-F0-9]{40})', 'Ethereum wallet address', True),  # Needs validation
                (r'(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34})', 'Bitcoin wallet address', True),  # Needs validation
                (r'coinhive|cryptonight|webminer', 'Known crypto mining library', False),
                (r'\.tk/|\.ml/|\.ga/|\.cf/', 'Suspicious free TLD domain', False),
            ]
            
            for pattern, description, needs_validation in malicious_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    is_valid = True
                    matched_value = match.group(0)
                    
                    # For cryptocurrency addresses, check if it's actual address or just test data
                    if needs_validation and ('Bitcoin' in description or 'Ethereum' in description):
                        context = content[max(0, match.start()-100):min(len(content), match.end()+100)]
                        
                        # False positive indicators
                        test_indicators = [
                            'test', 'example', 'sample', 'demo', 
                            'placeholder', 'regex', 'pattern', 
                            'validate', 'format', '//',  # In comments
                            '/*', 'comment'
                        ]
                        
                        # Check if it's in test/example context
                        if any(indicator in context.lower() for indicator in test_indicators):
                            is_valid = False
                        
                        # Bitcoin addresses: Check if it's part of a regex pattern or validation code
                        if 'Bitcoin' in description:
                            # If surrounded by regex delimiters or in validation context, skip
                            context_before = context[max(0, match.start()-20):match.start()]
                            if re.search(r'[/\[\]()|]', context_before):
                                is_valid = False
                            
                            # Common test addresses
                            if matched_value in ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa']:  # Genesis block address
                                is_valid = False
                            
                            # Check if it's hex data (lowercase hex chars = crypto data, not address)
                            # Real Bitcoin addresses use Base58 (no lowercase 'o', 'l', '0', 'i')
                            if re.match(r'^[0-9a-f]+$', matched_value):  # Pure hex = false positive
                                is_valid = False
                            
                            # Bitcoin addresses should NOT be all lowercase or all one case
                            if matched_value.islower() or matched_value.isupper():
                                is_valid = False
                            
                            # Check context - if in array of hex strings, it's crypto data not addresses
                            if re.search(r'["\'][0-9a-f]{40,}["\']', context):  # Hex strings nearby
                                is_valid = False
                            
                            # Check if it's numeric data that matches pattern (e.g., invoice numbers, IDs)
                            # Bitcoin addresses should have mixed case and varied characters
                            if matched_value.isdigit() or len(set(matched_value)) < 15:  # Too uniform
                                is_valid = False
                        
                        # Ethereum addresses: Similar checks
                        if 'Ethereum' in description:
                            if re.search(r'[/\[\]()|]', context[max(0, match.start()-20):match.start()]):
                                is_valid = False
                    
                    if is_valid:
                        context_snippet = content[max(0, match.start()-80):min(len(content), match.end()+80)]
                        self.supply_chain_risks.append({
                            'source': script_url,
                            'pattern': pattern,
                            'risk': description,
                            'severity': 'CRITICAL',
                            'matched_value': matched_value,
                            'context': context_snippet.strip()[:200]
                        })
            
            # Check for typosquatting in package/library names
            popular_libs = ['react', 'angular', 'vue', 'jquery', 'lodash', 'axios', 'moment']
            for lib in popular_libs:
                # Common typos: extra char, missing char, swapped chars
                typo_patterns = [
                    lib + r'[a-z]',  # Extra char
                    lib[:-1] + r'[a-z]',  # Different last char
                ]
                for typo in typo_patterns:
                    if re.search(r'\b' + typo + r'\b', script_url, re.IGNORECASE):
                        self.typosquatting_risks.append({
                            'source': script_url,
                            'suspected_typo': typo,
                            'legitimate': lib,
                            'risk': 'Possible typosquatting attack'
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[SUPPLY-CHAIN]{Style.RESET_ALL} Error: {e}")
    
    def _detect_dom_xss_sinks(self, content, source_url):
        """Detect dangerous DOM XSS sinks"""
        try:
            xss_sinks = {
                'innerHTML': [
                    r'\.innerHTML\s*=\s*(?![\'""])',
                    r'element\.innerHTML\s*\+=',
                    r'\$\([^\)]+\)\.html\(',  # jQuery .html()
                ],
                'document.write': [
                    r'document\.write\s*\(',
                    r'document\.writeln\s*\(',
                ],
                'eval': [
                    r'\beval\s*\(',
                    r'setTimeout\s*\(\s*[\'"`]',  # setTimeout with string
                    r'setInterval\s*\(\s*[\'"`]',  # setInterval with string
                    r'Function\s*\(',  # Function constructor
                ],
                'location': [
                    r'location\.href\s*=',
                    r'location\.replace\s*\(',
                    r'location\.assign\s*\(',
                ],
                'script injection': [
                    r'\.src\s*=\s*(?![\'""])',  # Dynamic script src
                    r'createElement\s*\(\s*[\'"`]script',
                ],
            }
            
            for sink_type, patterns in xss_sinks.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        context = content[max(0, match.start()-50):min(len(content), match.end()+50)]
                        self.dom_xss_sinks.append({
                            'type': sink_type,
                            'pattern': pattern,
                            'context': context.strip(),
                            'source': source_url,
                            'severity': 'HIGH' if sink_type in ['eval', 'document.write'] else 'MEDIUM'
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[DOM-XSS]{Style.RESET_ALL} Error: {e}")
    
    def _detect_prototype_pollution(self, content, source_url):
        """Detect prototype pollution vulnerabilities"""
        try:
            pollution_patterns = [
                (r'__proto__\s*\[', 'Direct __proto__ access'),
                (r'constructor\s*\[\s*[\'"`]prototype', 'Constructor.prototype manipulation'),
                (r'Object\.prototype\s*\.', 'Object.prototype modification'),
                (r'\.merge\s*\(', 'Potential vulnerable merge function'),
                (r'\.extend\s*\(', 'Potential vulnerable extend function'),
                (r'\.assign\s*\(\s*\{\s*\}', 'Object.assign with empty object'),
                (r'for\s*\(\s*(?:let|var|const)\s+key\s+in\s+', 'for-in loop without hasOwnProperty'),
            ]
            
            for pattern, description in pollution_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = content[max(0, match.start()-80):min(len(content), match.end()+80)]
                    self.prototype_pollution.append({
                        'pattern': description,
                        'context': context.strip()[:200],
                        'source': source_url,
                        'severity': 'HIGH' if '__proto__' in pattern else 'MEDIUM'
                    })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[PROTOTYPE-POLLUTION]{Style.RESET_ALL} Error: {e}")
    
    def _detect_csti_vulnerabilities(self, content, source_url):
        """Detect Client-Side Template Injection vulnerabilities"""
        try:
            csti_patterns = [
                (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML - XSS risk'),
                (r'v-html\s*=', 'Vue v-html directive - XSS risk'),
                (r'\{\{.*?\}\}', 'Template expression - possible injection'),
                (r'\[innerHTML\]\s*=', 'Angular innerHTML binding'),
                (r'ng-bind-html', 'Angular ng-bind-html - XSS risk'),
                (r'\$scope\.\$eval\s*\(', 'Angular $eval - code injection risk'),
                (r'\$compile\s*\(', 'Angular $compile with user input'),
            ]
            
            for pattern, description in csti_patterns:
                if re.search(pattern, content):
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        context = content[max(0, match.start()-60):min(len(content), match.end()+60)]
                        self.csti_vulns.append({
                            'type': description,
                            'context': context.strip()[:200],
                            'source': source_url,
                            'severity': 'HIGH'
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[CSTI]{Style.RESET_ALL} Error: {e}")
    
    def _detect_high_entropy_secrets(self, content, source_url):
        """Detect high-entropy strings that might be secrets"""
        try:
            import math
            from collections import Counter
            
            def calculate_entropy(string):
                """Calculate Shannon entropy of a string"""
                if not string:
                    return 0
                entropy = 0
                counter = Counter(string)
                length = len(string)
                for count in counter.values():
                    probability = count / length
                    if probability > 0:
                        entropy -= probability * math.log2(probability)
                return entropy
            
            # Find strings that look like secrets (long alphanumeric strings)
            secret_candidates = re.findall(r'[\'"`]([A-Za-z0-9+/=_-]{32,})[\'"`]', content)
            
            # False positive filters
            false_positive_patterns = [
                r'^[0-9a-f]{64}$',  # Common hash placeholder
                r'^[A-Za-z0-9+/]+={0,2}$',  # Pure base64 alphabet (not actual encoded data)
                r'^0123456789',  # Sequential numbers
                r'^ABCDEFGHIJKLMNOP',  # Alphabets
                r'^[a-z]{32,}$',  # All lowercase (likely not a secret)
                r'^[A-Z]{32,}$',  # All uppercase (likely constant)
            ]
            
            for candidate in secret_candidates[:20]:  # Limit to first 20
                entropy = calculate_entropy(candidate)
                
                # High entropy (> 4.5) suggests randomness (secrets/tokens)
                if entropy > 4.5 and len(candidate) >= 32:
                    # Skip common false positives
                    is_false_positive = False
                    
                    # Check if it's a known alphabet/charset (not actual data)
                    if candidate in ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', 
                                   '0123456789abcdefghijklmnopqrstuvwxyz',
                                   'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']:
                        is_false_positive = True
                    
                    # Check false positive patterns
                    for fp_pattern in false_positive_patterns:
                        if re.match(fp_pattern, candidate):
                            is_false_positive = True
                            break
                    
                    # Check for common test/placeholder strings
                    if any(fp in candidate.lower() for fp in ['lorem', 'ipsum', 'example', 'test', 'xxxx', '0000', 'aaaa', 'placeholder']):
                        is_false_positive = True
                    
                    # Must have good mix of characters (not just repeating pattern)
                    unique_chars = len(set(candidate))
                    if unique_chars < 10:  # Too few unique characters
                        is_false_positive = True
                    
                    if not is_false_positive:
                        self.high_entropy_secrets.append({
                            'value': candidate[:100] + ('...' if len(candidate) > 100 else ''),
                            'entropy': round(entropy, 2),
                            'length': len(candidate),
                            'source': source_url,
                            'type': 'High-entropy string (possible secret/token)'
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[ENTROPY]{Style.RESET_ALL} Error: {e}")
    
    def _detect_private_keys(self, content, source_url):
        """Detect private keys and certificates"""
        try:
            key_patterns = [
                (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[^-]{20,}', 'Private Key'),  # Must have content after header
                (r'-----BEGIN OPENSSH PRIVATE KEY-----[^-]{20,}', 'OpenSSH Private Key'),
                (r'-----BEGIN PGP PRIVATE KEY BLOCK-----[^-]{20,}', 'PGP Private Key'),
                (r'-----BEGIN ENCRYPTED PRIVATE KEY-----[^-]{20,}', 'Encrypted Private Key'),
                (r'"private_key"\s*:\s*"[A-Za-z0-9+/=\n]{100,}"', 'JSON Private Key'),  # Actual key content
                (r'privateKey\s*[:=]\s*[\'"`][A-Za-z0-9+/=\n]{100,}[\'"`]', 'Private Key Variable'),  # Actual key value
            ]
            
            for pattern, key_type in key_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    matched_text = match.group(0)
                    
                    # Filter false positives: Just the header string literal, not actual keys
                    # Real keys have base64 content after the header
                    if '-----BEGIN' in matched_text:
                        # Check if there's actual key material (base64 lines) after the header
                        after_header = matched_text.split('-----BEGIN')[1] if '-----BEGIN' in matched_text else ''
                        
                        # Skip if it's just a string literal like: "-----BEGIN RSA PRIVATE KEY-----\n"
                        # Real keys have substantial base64 content
                        if len(after_header.strip()) < 50:
                            continue
                            
                        # Skip if it's in a comment or example
                        context_before = content[max(0, match.start()-100):match.start()]
                        if any(indicator in context_before for indicator in ['example', 'test', '//', '/*', 'comment', 'sample']):
                            continue
                    
                    context = content[match.start():min(len(content), match.end()+200)]
                    self.private_keys.append({
                        'type': key_type,
                        'context': context[:300],
                        'source': source_url,
                        'severity': 'CRITICAL'
                    })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[PRIVATE-KEYS]{Style.RESET_ALL} Error: {e}")
    
    def _check_source_maps(self, script_url):
        """Check for exposed source map files"""
        try:
            map_url = script_url + '.map'
            response = requests.head(map_url, timeout=5, verify=False, headers=self.headers)
            
            if response.status_code == 200:
                self.source_maps.append({
                    'url': map_url,
                    'original_script': script_url,
                    'risk': 'Source map exposed - reveals original source code',
                    'severity': 'HIGH'
                })
                
        except Exception as e:
            pass  # Silently fail for source map checks
    
    def _detect_graphql(self, content, source_url):
        """Detect GraphQL endpoints and configurations"""
        try:
            graphql_patterns = [
                (r'/graphql', 'GraphQL endpoint'),
                (r'graphql\s*\(', 'GraphQL function call'),
                (r'query\s+\{[^}]*\}', 'GraphQL query'),
                (r'mutation\s+\{[^}]*\}', 'GraphQL mutation'),
                (r'__schema\s*\{', 'GraphQL introspection query'),
                (r'IntrospectionQuery', 'GraphQL introspection'),
            ]
            
            for pattern, description in graphql_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches[:3]:  # Limit to 3 per pattern
                        context = content[max(0, match.start()-50):min(len(content), match.end()+100)]
                        self.graphql_endpoints.append({
                            'type': description,
                            'context': context.strip()[:200],
                            'source': source_url
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[GRAPHQL]{Style.RESET_ALL} Error: {e}")
    
    def _detect_postmessage_issues(self, content, source_url):
        """Detect postMessage security issues"""
        try:
            # Find postMessage senders
            sender_pattern = r'postMessage\s*\('
            if re.search(sender_pattern, content):
                matches = re.finditer(sender_pattern, content)
                for match in matches:
                    context = content[max(0, match.start()-100):min(len(content), match.end()+100)]
                    
                    # Check if origin is validated
                    has_origin_check = bool(re.search(r'origin\s*[!=]=', context))
                    
                    self.postmessage_issues.append({
                        'type': 'postMessage sender',
                        'context': context.strip()[:200],
                        'has_origin_validation': has_origin_check,
                        'source': source_url,
                        'risk': 'Missing origin validation' if not has_origin_check else 'Review origin validation'
                    })
            
            # Find message event listeners
            listener_pattern = r'addEventListener\s*\(\s*[\'"`]message[\'"`]'
            if re.search(listener_pattern, content):
                matches = re.finditer(listener_pattern, content)
                for match in matches:
                    context = content[max(0, match.start()-100):min(len(content), match.end()+200)]
                    has_origin_check = bool(re.search(r'event\.origin\s*[!=]=', context))
                    
                    self.postmessage_issues.append({
                        'type': 'message event listener',
                        'context': context.strip()[:200],
                        'has_origin_validation': has_origin_check,
                        'source': source_url,
                        'risk': 'CRITICAL - No origin check' if not has_origin_check else 'Review origin validation',
                        'severity': 'CRITICAL' if not has_origin_check else 'MEDIUM'
                    })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[POSTMESSAGE]{Style.RESET_ALL} Error: {e}")
    
    def _detect_ssrf_vectors(self, content, source_url):
        """Detect potential SSRF vulnerabilities"""
        try:
            ssrf_patterns = [
                (r'fetch\s*\(\s*(?:url|endpoint|target)', 'fetch() with variable URL'),
                (r'XMLHttpRequest.*?open\s*\([^,]+,\s*(?![\'""])', 'XHR with dynamic URL'),
                (r'\.load\s*\(\s*(?:url|path)', 'Dynamic resource loading'),
                (r'import\s*\(\s*[^\'"`]', 'Dynamic import with variable'),
                (r'new\s+WebSocket\s*\(\s*(?![\'""])', 'WebSocket with dynamic URL'),
            ]
            
            for pattern, description in ssrf_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = content[max(0, match.start()-80):min(len(content), match.end()+80)]
                    self.ssrf_vectors.append({
                        'type': description,
                        'context': context.strip()[:200],
                        'source': source_url,
                        'severity': 'MEDIUM'
                    })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[SSRF]{Style.RESET_ALL} Error: {e}")
    
    def _detect_storage_exposure(self, content, source_url):
        """Detect localStorage/sessionStorage security issues"""
        try:
            storage_patterns = [
                (r'localStorage\.setItem\s*\(\s*[\'"`](?:token|jwt|auth|password|secret)', 'Sensitive data in localStorage'),
                (r'sessionStorage\.setItem\s*\(\s*[\'"`](?:token|jwt|auth|password)', 'Sensitive data in sessionStorage'),
                (r'localStorage\.getItem\s*\(\s*[\'"`](?:token|jwt|auth)', 'Retrieving auth from localStorage'),
                (r'document\.cookie\s*=.*?(?:token|jwt|session)', 'Sensitive cookie without security flags'),
            ]
            
            for pattern, description in storage_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = content[max(0, match.start()-60):min(len(content), match.end()+100)]
                    
                    # Check if encrypted before storage
                    has_encryption = bool(re.search(r'encrypt|crypto|aes', context, re.IGNORECASE))
                    
                    self.storage_exposure.append({
                        'type': description,
                        'context': context.strip()[:200],
                        'encrypted': has_encryption,
                        'source': source_url,
                        'risk': 'Unencrypted sensitive data' if not has_encryption else 'Review encryption implementation',
                        'severity': 'HIGH' if not has_encryption else 'MEDIUM'
                    })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[STORAGE]{Style.RESET_ALL} Error: {e}")
    
    def _detect_fingerprinting(self, content, source_url):
        """Detect browser fingerprinting techniques"""
        try:
            fingerprinting_techniques = [
                (r'canvas\.toDataURL|getImageData', 'Canvas fingerprinting'),
                (r'getContext\s*\(\s*[\'"`]webgl', 'WebGL fingerprinting'),
                (r'AudioContext|webkitAudioContext', 'Audio fingerprinting'),
                (r'navigator\.plugins', 'Plugin enumeration'),
                (r'navigator\.getBattery', 'Battery API fingerprinting'),
                (r'document\.fonts\.check', 'Font enumeration'),
                (r'navigator\.deviceMemory', 'Device memory fingerprinting'),
                (r'navigator\.hardwareConcurrency', 'Hardware fingerprinting'),
            ]
            
            for pattern, technique in fingerprinting_techniques:
                if re.search(pattern, content, re.IGNORECASE):
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        context = content[max(0, match.start()-50):min(len(content), match.end()+50)]
                        self.fingerprinting.append({
                            'technique': technique,
                            'context': context.strip()[:150],
                            'source': source_url
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[FINGERPRINT]{Style.RESET_ALL} Error: {e}")
    
    def _detect_wasm(self, content, source_url):
        """Detect WebAssembly modules"""
        try:
            wasm_patterns = [
                (r'\.wasm[\'")\s]', 'WASM file reference'),
                (r'WebAssembly\.instantiate', 'WASM instantiation'),
                (r'WebAssembly\.compile', 'WASM compilation'),
                (r'importObject.*?env', 'WASM import object'),
            ]
            
            for pattern, description in wasm_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        context = content[max(0, match.start()-60):min(len(content), match.end()+100)]
                        self.wasm_modules.append({
                            'type': description,
                            'context': context.strip()[:200],
                            'source': source_url
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[WASM]{Style.RESET_ALL} Error: {e}")
    
    def _detect_service_workers(self, content, source_url):
        """Detect Service Worker implementations"""
        try:
            sw_patterns = [
                (r'navigator\.serviceWorker\.register', 'Service Worker registration'),
                (r'self\.addEventListener\s*\(\s*[\'"`]install', 'Service Worker install event'),
                (r'self\.addEventListener\s*\(\s*[\'"`]fetch', 'Service Worker fetch event'),
                (r'cache\.addAll|cache\.add\(', 'Cache API usage'),
                (r'caches\.open\(', 'Cache storage'),
            ]
            
            for pattern, description in sw_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        context = content[max(0, match.start()-60):min(len(content), match.end()+100)]
                        self.service_workers.append({
                            'type': description,
                            'context': context.strip()[:200],
                            'source': source_url
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[SERVICE-WORKER]{Style.RESET_ALL} Error: {e}")
    
    def _detect_webrtc_leaks(self, content, source_url):
        """Detect WebRTC IP leak vectors"""
        try:
            webrtc_patterns = [
                (r'RTCPeerConnection|webkitRTCPeerConnection', 'WebRTC Peer Connection'),
                (r'createDataChannel', 'WebRTC Data Channel'),
                (r'iceServers|stun:|turn:', 'STUN/TURN server configuration'),
            ]
            
            for pattern, description in webrtc_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        context = content[max(0, match.start()-60):min(len(content), match.end()+100)]
                        self.webrtc_leaks.append({
                            'type': description,
                            'context': context.strip()[:200],
                            'source': source_url,
                            'risk': 'Potential IP address leak'
                        })
                        
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[WEBRTC]{Style.RESET_ALL} Error: {e}")
    
    def _detect_obfuscation(self, content, source_url):
        """Detect JavaScript obfuscation"""
        try:
            obfuscation_indicators = [
                (r'eval\s*\(\s*(?:atob|unescape|decodeURI)', 'Eval with decoding - likely obfuscated'),
                (r'String\.fromCharCode\s*\([\d,\s]+\)', 'CharCode obfuscation'),
                (r'_0x[a-f0-9]{4,}', 'Hex variable names (obfuscator pattern)'),
                (r'\[\'.*?\'\]\[\'.*?\'\]', 'Bracket notation obfuscation'),
                (r'var\s+_0x', 'Common obfuscator variable pattern'),
            ]
            
            obfuscation_score = 0
            found_patterns = []
            
            for pattern, description in obfuscation_indicators:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    obfuscation_score += len(matches)
                    found_patterns.append(description)
                    
            if obfuscation_score > 3:  # If multiple indicators found
                self.obfuscated_code.append({
                    'source': source_url,
                    'score': obfuscation_score,
                    'patterns': ', '.join(set(found_patterns)),
                    'risk': 'Code appears to be obfuscated - manual review recommended',
                    'severity': 'HIGH' if obfuscation_score > 10 else 'MEDIUM'
                })
                
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[OBFUSCATION]{Style.RESET_ALL} Error: {e}")
    
    def _detect_weak_crypto(self, content, source_url):
        """Detect weak cryptographic implementations"""
        try:
            weak_crypto_patterns = [
                # Math.random() for crypto - needs context check
                (r'Math\.random\s*\(\s*\)', 'Math.random() used for crypto - INSECURE', True),  # True = needs context check
                (r'md5\s*\(', 'MD5 hashing - cryptographically broken', False),
                (r'sha1\s*\(', 'SHA1 hashing - deprecated', False),
                (r'createCipheriv\s*\(\s*[\'"`]des', 'DES encryption - insecure', False),
                (r'createCipheriv\s*\(\s*[\'"`][^\'"`]*ecb', 'ECB mode - insecure block cipher mode', False),
                (r'PBKDF2.*?iterations?\s*:\s*([1-9]\d{0,3})\b', 'Low PBKDF2 iterations (<10000)', False),
                (r'new\s+Date\s*\(\s*\)\.getTime\s*\(\s*\)', 'Timestamp as crypto seed - predictable', True),
            ]
            
            for pattern, description, needs_context in weak_crypto_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    # Get surrounding context
                    context = content[max(0, match.start()-150):min(len(content), match.end()+150)]
                    
                    is_valid_finding = True
                    
                    # For Math.random(), check if it's actually used for crypto
                    if 'Math.random' in description and needs_context:
                        # Only flag if used in crypto context
                        crypto_keywords = ['crypto', 'encrypt', 'token', 'key', 'secret', 'password', 'salt', 'iv', 'nonce', 'random']
                        
                        # Check if it's in crypto context (within 200 chars)
                        has_crypto_context = any(keyword in context.lower() for keyword in crypto_keywords)
                        
                        # Common false positives - legitimate non-crypto uses
                        legitimate_uses = [
                            'Math.random().toString(36)',  # ID generation (not crypto)
                            'slice(2)',  # ID generation
                            'Math.floor',  # Random numbers for UI/animations
                            'animation',
                            'color',
                            'position',
                            'delay',
                            'timeout',
                        ]
                        
                        is_legitimate = any(use in context for use in legitimate_uses)
                        
                        # Only flag if in crypto context AND not legitimate use
                        if not has_crypto_context or is_legitimate:
                            is_valid_finding = False
                    
                    # For timestamps, check if actually used for crypto
                    elif 'Timestamp' in description and needs_context:
                        crypto_keywords = ['seed', 'random', 'crypto', 'encrypt', 'key']
                        has_crypto_context = any(keyword in context.lower() for keyword in crypto_keywords)
                        
                        if not has_crypto_context:
                            is_valid_finding = False
                    
                    # For ECB mode, avoid false positives from string literals
                    elif 'ECB' in description or 'ecb' in pattern:
                        # Check if it's in actual code, not just a string or comment
                        if re.search(r'createCipheriv\s*\(\s*[\'"`][^\'"`]*ecb', context, re.IGNORECASE):
                            is_valid_finding = True
                        else:
                            # Might be just 'ecb' in a string or variable name
                            # Need stricter check
                            if not re.search(r'[\'"`].*?ecb.*?[\'"`]', context, re.IGNORECASE):
                                is_valid_finding = False
                    
                    if is_valid_finding:
                        self.weak_crypto.append({
                            'type': description,
                            'context': context.strip()[:200],
                            'source': source_url,
                            'severity': 'CRITICAL' if 'Math.random' in description or 'MD5' in description else 'HIGH'
                        })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[WEAK-CRYPTO]{Style.RESET_ALL} Error: {e}")
    
    def _detect_clickjacking(self, content, source_url):
        """Detect clickjacking protection and frame-related security"""
        try:
            # Check for frame busting code
            frame_busting_patterns = [
                r'top\.location\s*!=\s*self\.location',
                r'if\s*\(\s*top\s*!=\s*self\s*\)',
                r'parent\.location\s*=\s*self\.location',
            ]
            
            has_frame_busting = False
            for pattern in frame_busting_patterns:
                if re.search(pattern, content):
                    has_frame_busting = True
                    break
            
            # Check for frame-related code
            frame_patterns = [
                (r'<iframe', 'iframe usage'),
                (r'window\.frames', 'Frame access'),
                (r'parent\.postMessage', 'Cross-frame communication'),
            ]
            
            for pattern, description in frame_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.clickjacking_vectors.append({
                        'type': description,
                        'has_frame_busting': has_frame_busting,
                        'source': source_url,
                        'risk': 'No frame busting detected' if not has_frame_busting else 'Frame busting present'
                    })
                    
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[CLICKJACKING]{Style.RESET_ALL} Error: {e}")

    # ==================================================================================
    # END OF ADVANCED DETECTION METHODS
    # ==================================================================================
    # CORS MISCONFIGURATION DETECTION
    # ==================================================================================
    
    def _detect_cors_issues(self, url):
        """
        Detect CORS misconfigurations that could lead to security vulnerabilities
        
        Tests:
        1. Wildcard (*) in Access-Control-Allow-Origin
        2. Null origin reflection
        3. Arbitrary origin reflection
        4. Credentials with wildcard (CRITICAL)
        """
        try:
            test_origins = [
                'https://evil.com',
                'https://attacker.com',
                'null',
                'http://localhost',
            ]
            
            for origin in test_origins:
                headers = {
                    'Origin': origin,
                    'User-Agent': self.headers['User-Agent']
                }
                
                # Test both GET and OPTIONS (preflight)
                for method in ['GET', 'OPTIONS']:
                    try:
                        if method == 'GET':
                            response = safe_request_get(url, timeout=args.timeout, headers=headers, max_retries=2)
                        else:
                            response = requests.options(url, timeout=args.timeout, verify=False, headers=headers)
                        
                        if not response:
                            continue
                        
                        acao = response.headers.get('Access-Control-Allow-Origin', '')
                        acac = response.headers.get('Access-Control-Allow-Credentials', '')
                        
                        # Check for wildcard
                        if acao == '*':
                            issue = {
                                'type': 'Wildcard CORS',
                                'severity': 'HIGH' if acac.lower() == 'true' else 'MEDIUM',
                                'origin_tested': origin,
                                'source': url,
                                'details': f'Access-Control-Allow-Origin: * (Credentials: {acac})',
                                'method': method
                            }
                            if not any(i.get('type') == 'Wildcard CORS' and i.get('source') == url for i in self.cors_issues):
                                self.cors_issues.append(issue)
                        
                        # Check for origin reflection
                        elif acao == origin:
                            issue = {
                                'type': 'Origin Reflection',
                                'severity': 'CRITICAL' if acac.lower() == 'true' else 'HIGH',
                                'origin_tested': origin,
                                'source': url,
                                'details': f'Reflects arbitrary origin: {origin} (Credentials: {acac})',
                                'method': method
                            }
                            if not any(i.get('origin_tested') == origin and i.get('source') == url for i in self.cors_issues):
                                self.cors_issues.append(issue)
                        
                        # Check for null origin (special case)
                        elif origin == 'null' and acao == 'null':
                            issue = {
                                'type': 'Null Origin Accepted',
                                'severity': 'HIGH',
                                'origin_tested': 'null',
                                'source': url,
                                'details': f'Accepts null origin (Credentials: {acac})',
                                'method': method
                            }
                            if not any(i.get('type') == 'Null Origin Accepted' and i.get('source') == url for i in self.cors_issues):
                                self.cors_issues.append(issue)
                    
                    except Exception as e:
                        if args.verbose:
                            logger.debug(f"CORS test failed for {url} with origin {origin}: {e}")
                        continue
        
        except Exception as e:
            if args.verbose:
                logger.debug(f"CORS detection failed for {url}: {e}")
    
    # ==================================================================================

    def _find_ajax_calls(self, content):
        """Find AJAX calls and HTTP requests in JavaScript"""
        ajax_patterns = [
            r'\.ajax\({[^}]*url:\s*[\'"`]([^\'"`,]+)[\'"`]',  # jQuery AJAX
            r'fetch\([\'"`]([^\'"`,]+)[\'"`]',  # Fetch API
            r'\.(?:get|post|put|delete|patch)\([\'"`]([^\'"`,]+)[\'"`]',  # HTTP methods
            r'XMLHttpRequest.*?open\([\'"`]\w+[\'"`],\s*[\'"`]([^\'"`,]+)[\'"`]',  # XMLHttpRequest
            r'axios\.(?:get|post|put|delete|patch)\([\'"`]([^\'"`,]+)[\'"`]'  # Axios
        ]

        for pattern in ajax_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                self.ajax_calls.add(match)

    def _extract_event_handlers(self, content):
        """Extract event handlers from JavaScript"""
        event_patterns = [
            r'on(?:click|load|change|submit|focus|blur|keypress|keydown|keyup)\s*=\s*[\'"`]?([a-zA-Z_$][a-zA-Z0-9_$]*)',
            r'addEventListener\([\'"`]([\w-]+)[\'"`]',
            r'\.on\([\'"`]([\w-]+)[\'"`]'
        ]

        for pattern in event_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                self.event_handlers.add(match)

    def _find_imports(self, content, base_url):
        """Find JavaScript imports and dependencies"""
        import_patterns = [
            r'import\s+.*?from\s*[\'"`](.*?)[\'"`]',
            r'require\([\'"`](.*?)[\'"`]\)',
            r'import\([\'"`](.*?)[\'"`]\)',
            r'<script\s+src=[\'"`](.*?\.js)[\'"`]'
        ]

        for pattern in import_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.startswith(('http://', 'https://')):
                    self.js_files.add(match)
                elif match.startswith('/'):
                    self.js_files.add(urljoin(base_url, match))

    # ==================================================================================
    # EXPORT FUNCTIONALITY - JSON/CSV/HTML Reports
    # ==================================================================================
    
    def export_json(self, filename='jsrecon_report.json', target_url=''):
        """Export all JS reconnaissance findings to JSON format"""
        try:
            import datetime
            
            report = {
                'metadata': {
                    'tool': 'SubFuzz JS Reconnaissance',
                    'version': __version__,
                    'scan_date': datetime.datetime.now().isoformat(),
                    'target_url': target_url,
                },
                'summary': {
                    'total_js_files': len(self.js_files),
                    'total_endpoints': len(self.discovered_endpoints),
                    'total_secrets': len(self.secrets),
                    'total_frameworks': len(self.frameworks),
                    'total_vulnerabilities': (
                        len(self.dom_xss_sinks) + len(self.prototype_pollution) + 
                        len(self.csti_vulns) + len(self.ssrf_vectors) +
                        len(self.weak_crypto) + len(self.clickjacking_vectors)
                    ),
                },
                'frameworks': self.frameworks,
                'javascript_files': list(self.js_files),
                'endpoints': {
                    'all_endpoints': self.discovered_endpoints,
                    'api_endpoints': self.api_patterns,
                },
                'secrets': self.secrets,
                'vulnerabilities': {
                    'supply_chain_risks': self.supply_chain_risks,
                    'dom_xss_sinks': self.dom_xss_sinks,
                    'prototype_pollution': self.prototype_pollution,
                    'csti_vulnerabilities': self.csti_vulns,
                    'high_entropy_secrets': self.high_entropy_secrets,
                    'private_keys': self.private_keys,
                    'source_maps': self.source_maps,
                    'graphql_endpoints': self.graphql_endpoints,
                    'postmessage_issues': self.postmessage_issues,
                    'ssrf_vectors': self.ssrf_vectors,
                    'storage_exposure': self.storage_exposure,
                    'fingerprinting': self.fingerprinting,
                    'wasm_modules': self.wasm_modules,
                    'service_workers': self.service_workers,
                    'webrtc_leaks': self.webrtc_leaks,
                    'obfuscated_code': self.obfuscated_code,
                    'weak_crypto': self.weak_crypto,
                    'clickjacking_vectors': self.clickjacking_vectors,
                    'cors_misconfigurations': self.cors_issues,
                },
                'code_analysis': {
                    'functions': list(self.functions),
                    'main_functions': self.main_functions,
                    'event_handlers': list(self.event_handlers),
                    'ajax_calls': list(self.ajax_calls),
                    'websockets': list(self.websockets),
                    'crypto_implementations': self.crypto_implementations,
                },
                'library_security': {
                    'vulnerable_libraries': self.vulnerable_libs,
                    'library_versions': self.library_versions,
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"{Fore.GREEN}[EXPORT]{Style.RESET_ALL} JSON report saved to: {filename}")
            return filename
            
        except Exception as e:
            print(f"{Fore.RED}[EXPORT]{Style.RESET_ALL} Failed to export JSON: {e}")
            return None
    
    def export_csv(self, filename='jsrecon_report.csv'):
        """Export findings to CSV format (vulnerabilities and secrets)"""
        try:
            import csv
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Severity', 'Finding', 'Source', 'Context'])
                
                # Supply chain risks
                for item in self.supply_chain_risks:
                    writer.writerow([
                        'Supply Chain',
                        item.get('severity', 'HIGH'),
                        item.get('type', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('details', '')[:200]
                    ])
                
                # DOM XSS Sinks
                for item in self.dom_xss_sinks:
                    writer.writerow([
                        'DOM XSS',
                        'CRITICAL',
                        item.get('sink', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('matched_value', '')[:200]
                    ])
                
                # Prototype Pollution
                for item in self.prototype_pollution:
                    writer.writerow([
                        'Prototype Pollution',
                        'HIGH',
                        item.get('pattern', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('matched_value', '')[:200]
                    ])
                
                # CSTI Vulnerabilities
                for item in self.csti_vulns:
                    writer.writerow([
                        'CSTI',
                        'HIGH',
                        item.get('template_type', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('matched_value', '')[:200]
                    ])
                
                # High Entropy Secrets
                for item in self.high_entropy_secrets:
                    writer.writerow([
                        'High Entropy Secret',
                        'CRITICAL',
                        f"Entropy: {item.get('entropy', 0):.2f}",
                        item.get('source', 'N/A'),
                        item.get('secret', '')[:100]
                    ])
                
                # Private Keys
                for item in self.private_keys:
                    writer.writerow([
                        'Private Key',
                        'CRITICAL',
                        item.get('type', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('matched_value', '')[:100]
                    ])
                
                # GraphQL Endpoints
                for item in self.graphql_endpoints:
                    writer.writerow([
                        'GraphQL',
                        'MEDIUM',
                        item.get('endpoint', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('details', '')[:200]
                    ])
                
                # SSRF Vectors
                for item in self.ssrf_vectors:
                    writer.writerow([
                        'SSRF',
                        'HIGH',
                        item.get('pattern', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('matched_value', '')[:200]
                    ])
                
                # Weak Crypto
                for item in self.weak_crypto:
                    writer.writerow([
                        'Weak Crypto',
                        'MEDIUM',
                        item.get('type', 'Unknown'),
                        item.get('source', 'N/A'),
                        item.get('matched_value', '')[:200]
                    ])
                
                # Traditional Secrets
                for secret in self.secrets:
                    writer.writerow([
                        'Secret',
                        'HIGH',
                        secret.get('category', 'Unknown'),
                        secret.get('source', 'N/A'),
                        secret.get('value', '')[:100]
                    ])
                
                # CORS Issues
                for cors in self.cors_issues:
                    writer.writerow([
                        'CORS Misconfiguration',
                        cors.get('severity', 'HIGH'),
                        cors.get('type', 'Unknown'),
                        cors.get('source', 'N/A'),
                        cors.get('details', '')[:200]
                    ])
            
            print(f"{Fore.GREEN}[EXPORT]{Style.RESET_ALL} CSV report saved to: {filename}")
            return filename
            
        except Exception as e:
            print(f"{Fore.RED}[EXPORT]{Style.RESET_ALL} Failed to export CSV: {e}")
            return None
    
    def export_html(self, filename='jsrecon_report.html', target_url=''):
        """Export findings to interactive HTML report with charts"""
        try:
            import datetime
            
            # Calculate statistics
            total_vulns = (
                len(self.dom_xss_sinks) + len(self.prototype_pollution) + 
                len(self.csti_vulns) + len(self.ssrf_vectors) +
                len(self.weak_crypto) + len(self.clickjacking_vectors) +
                len(self.postmessage_issues) + len(self.webrtc_leaks)
            )
            
            critical_count = len(self.dom_xss_sinks) + len(self.high_entropy_secrets) + len(self.private_keys)
            high_count = len(self.prototype_pollution) + len(self.csti_vulns) + len(self.ssrf_vectors) + len(self.secrets)
            medium_count = len(self.weak_crypto) + len(self.graphql_endpoints) + len(self.postmessage_issues)
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SubFuzz JS Reconnaissance Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f23; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .header h1 {{ color: white; font-size: 2.5em; margin-bottom: 10px; }}
        .header .meta {{ color: #f0f0f0; font-size: 0.9em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1a2e; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border-left: 4px solid #667eea; }}
        .stat-card h3 {{ color: #667eea; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }}
        .stat-card .number {{ font-size: 2.5em; font-weight: bold; color: white; }}
        .section {{ background: #1a1a2e; padding: 25px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .section h2 {{ color: #667eea; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        .finding {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ffd700; }}
        .finding.critical {{ border-left-color: #ff4757; }}
        .finding.high {{ border-left-color: #ff6348; }}
        .finding.medium {{ border-left-color: #ffa502; }}
        .finding.low {{ border-left-color: #26de81; }}
        .finding h4 {{ color: #ffd700; margin-bottom: 8px; }}
        .finding.critical h4 {{ color: #ff4757; }}
        .finding.high h4 {{ color: #ff6348; }}
        .finding.medium h4 {{ color: #ffa502; }}
        .finding .source {{ color: #888; font-size: 0.85em; margin: 5px 0; }}
        .finding .details {{ color: #ccc; font-family: 'Courier New', monospace; font-size: 0.9em; background: #0f0f23; padding: 10px; border-radius: 3px; margin-top: 8px; overflow-x: auto; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.75em; font-weight: bold; margin-right: 8px; }}
        .badge.critical {{ background: #ff4757; color: white; }}
        .badge.high {{ background: #ff6348; color: white; }}
        .badge.medium {{ background: #ffa502; color: white; }}
        .badge.low {{ background: #26de81; color: white; }}
        .badge.info {{ background: #667eea; color: white; }}
        .framework-list {{ display: flex; flex-wrap: wrap; gap: 10px; }}
        .framework-item {{ background: #667eea; color: white; padding: 8px 16px; border-radius: 20px; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2c2c44; }}
        th {{ background: #16213e; color: #667eea; font-weight: bold; }}
        tr:hover {{ background: #16213e; }}
        code {{ background: #0f0f23; padding: 2px 6px; border-radius: 3px; color: #ffd700; font-family: 'Courier New', monospace; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px; }}
        .summary-item {{ background: #16213e; padding: 15px; border-radius: 5px; text-align: center; }}
        .summary-item .count {{ font-size: 2em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 SubFuzz JS Reconnaissance Report</h1>
            <div class="meta">
                <strong>Target:</strong> {target_url}<br>
                <strong>Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                <strong>Tool Version:</strong> v{__version__}
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <h3>JavaScript Files</h3>
                <div class="number">{len(self.js_files)}</div>
            </div>
            <div class="stat-card">
                <h3>Endpoints Discovered</h3>
                <div class="number">{len(self.discovered_endpoints)}</div>
            </div>
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <div class="number">{total_vulns}</div>
            </div>
            <div class="stat-card">
                <h3>Secrets Found</h3>
                <div class="number">{len(self.secrets) + len(self.high_entropy_secrets) + len(self.private_keys)}</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Severity Distribution</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="count" style="color: #ff4757;">{critical_count}</div>
                    <div>Critical</div>
                </div>
                <div class="summary-item">
                    <div class="count" style="color: #ff6348;">{high_count}</div>
                    <div>High</div>
                </div>
                <div class="summary-item">
                    <div class="count" style="color: #ffa502;">{medium_count}</div>
                    <div>Medium</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🎨 Detected Frameworks & Libraries</h2>
            <div class="framework-list">
"""
            
            if self.frameworks:
                for framework, version in self.frameworks.items():
                    html_content += f'                <div class="framework-item">{framework} v{version}</div>\n'
            else:
                html_content += '                <p style="color: #888;">No frameworks detected</p>\n'
            
            html_content += """            </div>
        </div>
"""

            # DOM XSS Sinks
            if self.dom_xss_sinks:
                html_content += """
        <div class="section">
            <h2>⚠️ DOM XSS Sinks (CRITICAL)</h2>
"""
                for item in self.dom_xss_sinks[:20]:
                    html_content += f"""            <div class="finding critical">
                <h4><span class="badge critical">CRITICAL</span> {item.get('sink', 'Unknown Sink')}</h4>
                <div class="source">Source: {item.get('source', 'N/A')}</div>
                <div class="details">{item.get('matched_value', '')[:300]}</div>
            </div>
"""
                html_content += """        </div>
"""

            # High Entropy Secrets
            if self.high_entropy_secrets:
                html_content += """
        <div class="section">
            <h2>🔑 High Entropy Secrets (CRITICAL)</h2>
"""
                for item in self.high_entropy_secrets[:20]:
                    html_content += f"""            <div class="finding critical">
                <h4><span class="badge critical">CRITICAL</span> Entropy: {item.get('entropy', 0):.2f}</h4>
                <div class="source">Source: {item.get('source', 'N/A')}</div>
                <div class="details">{item.get('secret', '')[:200]}...</div>
            </div>
"""
                html_content += """        </div>
"""

            # Private Keys
            if self.private_keys:
                html_content += """
        <div class="section">
            <h2>🔐 Private Keys (CRITICAL)</h2>
"""
                for item in self.private_keys[:10]:
                    html_content += f"""            <div class="finding critical">
                <h4><span class="badge critical">CRITICAL</span> {item.get('type', 'Unknown Key Type')}</h4>
                <div class="source">Source: {item.get('source', 'N/A')}</div>
                <div class="details">{item.get('matched_value', '')[:150]}...</div>
            </div>
"""
                html_content += """        </div>
"""

            # Prototype Pollution
            if self.prototype_pollution:
                html_content += """
        <div class="section">
            <h2>💉 Prototype Pollution (HIGH)</h2>
"""
                for item in self.prototype_pollution[:15]:
                    html_content += f"""            <div class="finding high">
                <h4><span class="badge high">HIGH</span> {item.get('pattern', 'Unknown Pattern')}</h4>
                <div class="source">Source: {item.get('source', 'N/A')}</div>
                <div class="details">{item.get('matched_value', '')[:300]}</div>
            </div>
"""
                html_content += """        </div>
"""

            # SSRF Vectors
            if self.ssrf_vectors:
                html_content += """
        <div class="section">
            <h2>🌐 SSRF Vectors (HIGH)</h2>
"""
                for item in self.ssrf_vectors[:15]:
                    html_content += f"""            <div class="finding high">
                <h4><span class="badge high">HIGH</span> {item.get('pattern', 'Unknown Pattern')}</h4>
                <div class="source">Source: {item.get('source', 'N/A')}</div>
                <div class="details">{item.get('matched_value', '')[:300]}</div>
            </div>
"""
                html_content += """        </div>
"""

            # Weak Crypto
            if self.weak_crypto:
                html_content += """
        <div class="section">
            <h2>🔓 Weak Cryptography (MEDIUM)</h2>
"""
                for item in self.weak_crypto[:15]:
                    html_content += f"""            <div class="finding medium">
                <h4><span class="badge medium">MEDIUM</span> {item.get('type', 'Unknown Type')}</h4>
                <div class="source">Source: {item.get('source', 'N/A')}</div>
                <div class="details">{item.get('matched_value', '')[:300]}</div>
            </div>
"""
                html_content += """        </div>
"""

            # GraphQL Endpoints
            if self.graphql_endpoints:
                html_content += """
        <div class="section">
            <h2>📡 GraphQL Endpoints (MEDIUM)</h2>
"""
                for item in self.graphql_endpoints[:10]:
                    html_content += f"""            <div class="finding medium">
                <h4><span class="badge medium">MEDIUM</span> {item.get('endpoint', 'Unknown Endpoint')}</h4>
                <div class="source">Source: {item.get('source', 'N/A')}</div>
                <div class="details">{item.get('details', 'No additional details')}</div>
            </div>
"""
                html_content += """        </div>
"""

            # Secrets
            if self.secrets:
                html_content += """
        <div class="section">
            <h2>🔑 Exposed Secrets (HIGH)</h2>
"""
                for secret in self.secrets[:20]:
                    html_content += f"""            <div class="finding high">
                <h4><span class="badge high">HIGH</span> {secret.get('category', 'Unknown')}</h4>
                <div class="source">Source: {secret.get('source', 'N/A')}</div>
                <div class="details">{secret.get('value', '')[:150]}...</div>
            </div>
"""
                html_content += """        </div>
"""

            # Endpoints
            if self.discovered_endpoints:
                html_content += """
        <div class="section">
            <h2>🔗 Discovered Endpoints</h2>
            <table>
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Source File</th>
                    </tr>
                </thead>
                <tbody>
"""
                for endpoint in list(self.discovered_endpoints)[:50]:
                    if isinstance(endpoint, dict):
                        html_content += f"""                    <tr>
                        <td><code>{endpoint.get('endpoint', 'N/A')}</code></td>
                        <td>{endpoint.get('source', 'N/A')}</td>
                    </tr>
"""
                html_content += """                </tbody>
            </table>
        </div>
"""

            # Footer
            html_content += f"""
        <div class="header" style="margin-top: 40px; padding: 20px;">
            <p>Generated by <strong>SubFuzz v{__version__}</strong> - Advanced Security Fuzzing & Scanning Platform</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Author: {__author__} | License: {__license__}</p>
        </div>
    </div>
</body>
</html>
"""
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}[EXPORT]{Style.RESET_ALL} HTML report saved to: {filename}")
            print(f"{Fore.CYAN}[EXPORT]{Style.RESET_ALL} Open in browser: file://{os.path.abspath(filename)}")
            return filename
            
        except Exception as e:
            print(f"{Fore.RED}[EXPORT]{Style.RESET_ALL} Failed to export HTML: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return None

# ==================================================================================
# MODERN RECONNAISSANCE FEATURES (2025)
# ==================================================================================

# ---------------------------
# WAF DETECTION & FINGERPRINTING
# ---------------------------
def detect_waf(domain, url=None):
    """
    Comprehensive WAF/CDN/Security Detection
    Detects 20+ major WAF/security solutions through multiple methods
    
    Returns: dict with WAF info, confidence, bypass recommendations
    """
    if url is None:
        url = f"https://{domain}"
    
    # Extract domain from URL if needed
    from urllib.parse import urlparse
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    waf_info = {
        'detected': [],
        'confidence': {},
        'methods': {},
        'security_headers': {},
        'recommendations': []
    }
    
    # Check DNS/CNAME for infrastructure indicators
    cname_record = None
    try:
        import subprocess
        cname_result = subprocess.run(['dig', '+short', 'CNAME', domain], 
                                     capture_output=True, text=True, timeout=5)
        if cname_result.returncode == 0 and cname_result.stdout.strip():
            cname_record = cname_result.stdout.strip().lower()
    except:
        pass
    
    # WAF Signature Database
    WAF_SIGNATURES = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
            'server': ['cloudflare'],
            'cookies': ['__cfduid', '__cflb'],
            'response_codes': [403, 503],
            'response_patterns': ['cloudflare', 'attention required', 'ray id']
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-cf-id'],
            'server': ['awselb', 'aws'],
            'cname': ['.elb.amazonaws.com', '.awsglobalaccelerator.com', '.cloudfront.net'],
            'response_patterns': ['aws', 'request blocked']
        },
        'Imperva (Incapsula)': {
            'headers': ['x-iinfo', 'x-cdn'],
            'server': ['imperva', 'incapsula'],
            'cookies': ['incap_ses', 'visid_incap'],
            'response_patterns': ['incapsula', 'imperva']
        },
        'Akamai': {
            'headers': ['akamai-origin-hop', 'akamai-x-cache', 'akamai-x-get-request-id'],
            'server': ['akamaighost', 'akamai'],
            'response_patterns': ['akamai', 'reference #']
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'server': ['sucuri', 'cloudproxy'],
            'response_patterns': ['sucuri', 'access denied', 'blocked by sucuri']
        },
        'ModSecurity': {
            'headers': ['mod_security'],
            'server': ['mod_security', 'modsecurity'],
            'response_patterns': ['mod_security', '406 not acceptable']
        },
        'F5 BIG-IP': {
            'headers': ['x-wa-info', 'bigipserver'],
            'server': ['big-ip', 'bigip'],
            'cookies': ['f5_cspm', 'bigipserver', 'ts'],
            'response_patterns': ['f5', 'tmm_refused']
        },
        'Barracuda': {
            'headers': ['barra_counter_session', 'barracuda_'],
            'server': ['barracuda'],
            'cookies': ['barra_counter_session', 'barracuda'],
            'response_patterns': ['barracuda']
        },
        'Citrix NetScaler': {
            'headers': ['ns_af', 'citrix_ns_id', 'nsx_'],
            'server': ['netscaler', 'citrix'],
            'cookies': ['ns_af', 'citrix_ns_id'],
            'response_patterns': ['netscaler']
        },
        'Fortinet FortiWeb': {
            'headers': ['fortigate', 'fortiweb'],
            'server': ['fortinet', 'fortiweb'],
            'cookies': ['fortiweb'],
            'response_patterns': ['fortinet', 'fortiweb']
        },
        'AppTrana': {
            'headers': ['apptrana-request-id'],
            'server': ['apptrana'],
            'cookies': ['sess_map'],
            'response_patterns': ['apptrana']
        },
        'Wordfence': {
            'headers': ['wordfence'],
            'server': ['wordfence'],
            'response_patterns': ['wordfence', 'generated by wordfence']
        },
        'AWS Shield': {
            'headers': ['x-amzn-shield'],
            'server': ['aws-shield'],
            'response_patterns': ['aws shield']
        },
        'Azure Front Door': {
            'headers': ['x-azure-ref', 'x-fd-healthprobe'],
            'server': ['azure'],
            'response_patterns': ['azure front door']
        },
        'Google Cloud Armor': {
            'headers': ['x-cloud-trace-context', 'x-goog'],
            'server': ['gfe', 'google'],
            'response_patterns': ['error 403', 'your client does not have permission']
        },
        'Fastly': {
            'headers': ['fastly-debug-digest', 'x-fastly-request-id'],
            'server': ['fastly'],
            'response_patterns': ['fastly error']
        },
        'StackPath (MaxCDN)': {
            'headers': ['x-sp-cache', 'x-stackpath'],
            'server': ['stackpath'],
            'response_patterns': ['stackpath']
        },
        'Radware': {
            'headers': ['x-protected-by'],
            'server': ['radware'],
            'response_patterns': ['radware']
        },
        'DDoS-Guard': {
            'headers': ['x-ddos-protection'],
            'server': ['ddos-guard'],
            'response_patterns': ['ddos-guard']
        },
        'Wallarm': {
            'headers': ['nginx-wallarm'],
            'server': ['wallarm'],
            'response_patterns': ['wallarm']
        },
        'Nginx (Generic)': {
            'server': ['nginx'],
            'response_patterns': []
        },
        'PerimeterX': {
            'headers': ['x-px-'],
            'cookies': ['_px', '_pxhd'],
            'response_patterns': ['perimeterx', 'access denied']
        },
        'Reblaze': {
            'headers': ['x-rb-'],
            'cookies': ['rbzid'],
            'response_patterns': ['reblaze']
        },
        'Signal Sciences': {
            'headers': ['x-sigsci-'],
            'server': ['signal sciences'],
            'response_patterns': ['signal sciences']
        },
        'Astra Security': {
            'headers': ['x-astra-'],
            'response_patterns': ['astra']
        },
        'Edgecast': {
            'headers': ['x-ec-'],
            'server': ['eca', 'ecd', 'ecacc'],
            'response_patterns': ['edgecast']
        }
    }
    
    try:
        # Make HTTP request to target
        import requests as req_lib
        try:
            r = req_lib.get(url, timeout=10, verify=False, allow_redirects=True)
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[WAF]{Style.RESET_ALL} HTTP request failed: {e}")
            return waf_info
        
        # Extract response data
        headers = {k.lower(): v for k, v in r.headers.items()}
        cookies = {k.lower(): v for k, v in r.cookies.items()}
        response_text = r.text.lower() if r.text else ''
        status_code = r.status_code
        server_header = headers.get('server', '').lower()
        
        # Store security headers
        security_header_names = [
            'x-frame-options', 'x-xss-protection', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy',
            'x-permitted-cross-domain-policies', 'referrer-policy',
            'permissions-policy', 'cross-origin-embedder-policy',
            'cross-origin-opener-policy', 'cross-origin-resource-policy'
        ]
        
        for header in security_header_names:
            if header in headers:
                waf_info['security_headers'][header] = headers[header]
        
        # Check each WAF signature
        for waf_name, signatures in WAF_SIGNATURES.items():
            confidence = 0
            detection_methods = []
            
            # Check headers
            if 'headers' in signatures:
                for header_pattern in signatures['headers']:
                    for header_name in headers.keys():
                        if header_pattern in header_name:
                            confidence += 40
                            detection_methods.append(f"header:{header_name}")
                            break
            
            # Check server header
            if 'server' in signatures and server_header:
                for server_pattern in signatures['server']:
                    if server_pattern in server_header:
                        confidence += 30
                        detection_methods.append(f"server:{server_header}")
                        break
            
            # Check CNAME records (for infrastructure-based detection)
            if 'cname' in signatures and cname_record:
                for cname_pattern in signatures['cname']:
                    if cname_pattern in cname_record:
                        confidence += 30  # CNAME is strong indicator for infrastructure WAFs
                        detection_methods.append(f"cname:{cname_pattern}")
                        break
            
            # Check cookies
            if 'cookies' in signatures:
                for cookie_pattern in signatures['cookies']:
                    for cookie_name in cookies.keys():
                        if cookie_pattern in cookie_name:
                            confidence += 25
                            detection_methods.append(f"cookie:{cookie_name}")
                            break
            
            # Check response body patterns
            if 'response_patterns' in signatures:
                for pattern in signatures['response_patterns']:
                    if pattern in response_text:
                        confidence += 20
                        detection_methods.append(f"response_pattern:{pattern}")
                        break
            
            # Check response codes
            if 'response_codes' in signatures:
                if status_code in signatures['response_codes']:
                    confidence += 10
                    detection_methods.append(f"status_code:{status_code}")
            
            # If confidence > 30%, consider WAF detected
            if confidence >= 30:
                waf_info['detected'].append(waf_name)
                waf_info['confidence'][waf_name] = min(confidence, 100)
                waf_info['methods'][waf_name] = detection_methods
        
        # AI-Powered Advanced Bypass Recommendations
        if waf_info['detected']:
            detected_wafs = ', '.join(waf_info['detected'])
            
            # Detailed bypass strategies per WAF
            advanced_bypass_tips = {
                'Cloudflare': {
                    'origin_exposure': [
                        '🔍 Origin IP Discovery:',
                        '  • Check DNS history (SecurityTrails, DNSDumpster)',
                        '  • Look for IPv6 origin servers',
                        '  • Scan subdomains not behind Cloudflare',
                        '  • Check mail/FTP servers revealing origin'
                    ],
                    'bypass_techniques': [
                        '🎯 Bypass Methods:',
                        '  • Direct IP access with Host header',
                        '  • Rate limit testing (default: 100 req/min)',
                        '  • Cache poisoning via headers',
                        '  • HTTP/2 request smuggling'
                    ],
                    'payload_tips': [
                        '💉 Payload Strategies:',
                        '  • Use mixed encoding (URL + Unicode)',
                        '  • Try case variations in paths',
                        '  • Parameter pollution attacks',
                        '  • Bypass via allowed file extensions (.jpg?cmd=)'
                    ]
                },
                'AWS WAF': {
                    'config_weaknesses': [
                        '⚙️ Configuration Weaknesses:',
                        '  • Default AWS WAF has case-sensitive rules',
                        '  • Check for custom rule gaps',
                        '  • Test regional rule variations',
                        '  • CloudFront cache bypass techniques'
                    ],
                    'bypass_techniques': [
                        '🎯 Bypass Methods:',
                        '  • Mixed case SQL injection (SeLeCt)',
                        '  • Double URL encoding',
                        '  • Unicode normalization bypasses',
                        '  • HTTP verb tampering (POST → PUT)',
                        '  • X-Forwarded-For IP whitelisting'
                    ],
                    'payload_tips': [
                        '💉 Payload Strategies:',
                        '  • Use AWS-specific encodings',
                        '  • Try NULL byte injection (%00)',
                        '  • HPP (HTTP Parameter Pollution)',
                        '  • JSON/XML content-type confusion'
                    ]
                },
                'ModSecurity': {
                    'ruleset_analysis': [
                        '📋 Ruleset Analysis:',
                        '  • Detect OWASP CRS version',
                        '  • Check paranoia level (1-4)',
                        '  • Identify custom rules',
                        '  • Find disabled rule IDs'
                    ],
                    'bypass_techniques': [
                        '🎯 Bypass Methods:',
                        '  • NULL byte injection (%00)',
                        '  • Mixed case keywords (UnIoN)',
                        '  • Comment-based obfuscation (/**/)',
                        '  • Alternative syntax (UNION ALL SELECT)',
                        '  • Newline/tab character insertion'
                    ],
                    'payload_tips': [
                        '💉 Payload Strategies:',
                        '  • HPP to confuse parsers',
                        '  • Multipart/form-data encoding',
                        '  • Charset confusion (UTF-7, UTF-16)',
                        '  • Request method case variations'
                    ]
                },
                'Imperva (Incapsula)': {
                    'origin_exposure': [
                        '🔍 Origin Discovery:',
                        '  • Historical DNS records',
                        '  • SSL certificate CN/SAN names',
                        '  • Check for direct server access',
                        '  • Shodan/Censys for exposed ports'
                    ],
                    'bypass_techniques': [
                        '🎯 Bypass Methods:',
                        '  • IP rotation with residential proxies',
                        '  • Session fixation attacks',
                        '  • Cache poisoning',
                        '  • Request smuggling (CL.TE / TE.CL)'
                    ],
                    'payload_tips': [
                        '💉 Payload Strategies:',
                        '  • Vary User-Agent frequently',
                        '  • Use legitimate crawler UAs',
                        '  • Test different HTTP methods',
                        '  • Fragment payloads across requests'
                    ]
                },
                'Akamai': {
                    'config_analysis': [
                        '⚙️ Configuration Analysis:',
                        '  • Identify Akamai property',
                        '  • Check cache key composition',
                        '  • Test edge server behavior',
                        '  • Map CDN distribution'
                    ],
                    'bypass_techniques': [
                        '🎯 Bypass Methods:',
                        '  • Cache deception attacks',
                        '  • Pragma/Cache-Control manipulation',
                        '  • Edge Side Include (ESI) injection',
                        '  • Origin server direct access'
                    ]
                },
                'F5 BIG-IP': {
                    'fingerprinting': [
                        '🔍 Advanced Fingerprinting:',
                        '  • Detect ASM policy version',
                        '  • Identify learning mode status',
                        '  • Check for iRules customization',
                        '  • Map virtual servers'
                    ],
                    'bypass_techniques': [
                        '🎯 Bypass Methods:',
                        '  • Cookie tampering (TS/BigIP cookies)',
                        '  • HPP via parameter encoding',
                        '  • Protocol confusion (HTTP/2 downgrade)',
                        '  • Timing-based policy detection'
                    ]
                },
                'PerimeterX': {
                    'bot_detection': [
                        '🤖 Bot Detection Bypass:',
                        '  • Analyze _px cookie structure',
                        '  • Browser fingerprint spoofing',
                        '  • Mouse movement simulation',
                        '  • Headless browser detection bypass'
                    ],
                    'bypass_techniques': [
                        '🎯 Bypass Methods:',
                        '  • Real browser automation (Puppeteer)',
                        '  • Cookie replay attacks',
                        '  • Canvas fingerprint randomization',
                        '  • WebGL fingerprint spoofing'
                    ]
                },
                'Nginx (Generic)': {
                    'reconnaissance': [
                        '🔍 Nginx Analysis:',
                        '  • Check for ModSecurity module',
                        '  • Detect naxsi WAF module',
                        '  • Test for custom Lua scripts',
                        '  • Version disclosure check'
                    ],
                    'bypass_techniques': [
                        '🎯 Common Bypasses:',
                        '  • Path normalization bugs',
                        '  • Trailing slash confusion',
                        '  • Location block misconfigurations',
                        '  • Alias directive exploitation'
                    ]
                }
            }
            
            # Generic bypass techniques for any WAF
            generic_bypasses = {
                'encoding': [
                    '🔤 Encoding Techniques:',
                    '  • URL encoding (single/double)',
                    '  • Unicode encoding variations',
                    '  • HTML entity encoding',
                    '  • Base64 encoding',
                    '  • Hex encoding',
                    '  • UTF-7/UTF-16 charset'
                ],
                'obfuscation': [
                    '🎭 Obfuscation Methods:',
                    '  • Case variation (SeLeCt, UnIoN)',
                    '  • Comment injection (/**/, --)',
                    '  • Whitespace manipulation',
                    '  • NULL byte insertion',
                    '  • Newline characters (\\n, \\r)'
                ],
                'fragmentation': [
                    '🧩 Request Fragmentation:',
                    '  • Split payloads across parameters',
                    '  • HTTP Parameter Pollution',
                    '  • Multipart request abuse',
                    '  • Chunked encoding tricks',
                    '  • Pipeline multiple requests'
                ],
                'protocol': [
                    '🌐 Protocol-Level Attacks:',
                    '  • HTTP/2 request smuggling',
                    '  • HTTP verb tampering',
                    '  • Content-Type confusion',
                    '  • Transfer-Encoding tricks',
                    '  • Host header poisoning'
                ]
            }
            
            # Use AI to generate context-specific recommendations
            if ai_system.ollama_available:
                for waf in waf_info['detected']:
                    if waf in advanced_bypass_tips:
                        tips = advanced_bypass_tips[waf]
                        for category, tips_list in tips.items():
                            waf_info['recommendations'].extend(tips_list)
                    
                    # Add generic bypasses for unknown WAFs
                    if waf not in advanced_bypass_tips or waf == 'Nginx (Generic)':
                        waf_info['recommendations'].extend(generic_bypasses['encoding'])
                        waf_info['recommendations'].extend(generic_bypasses['obfuscation'])
        
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[WAF]{Style.RESET_ALL} Detection error: {e}")
    
    return waf_info

# ---------------------------
# CLOUD PROVIDER DETECTION
# ---------------------------
def detect_cloud_provider(domain, ip_address=None):
    """
    Detect cloud provider from IP ranges, headers, and DNS patterns
    Returns: AWS, Azure, GCP, Cloudflare, Fastly, Akamai, etc.
    """
    # Extract domain from URL if needed
    from urllib.parse import urlparse
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    cloud_info = {
        'provider': 'Unknown',
        'services': [],
        'evidence': [],
        'cdn': None,
        'waf': None,
        'region': None,
        'ips': []
    }
    
    try:
        import ipaddress
        import requests as req_lib
        
        # Check HTTP headers for cloud/CDN signatures
        url = f"https://{domain}"
        r = None
        try:
            r = req_lib.get(url, timeout=args.timeout if args.timeout else 10, verify=False, allow_redirects=True)
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[CLOUD]{Style.RESET_ALL} HTTP request failed: {e}")
            r = None
        
        if r:
            headers = r.headers
            
            # Server header detection
            server = headers.get('server', '').lower()
            
            # WAF Detection (check first)
            if 'apptrana' in server:
                cloud_info['waf'] = 'AppTrana'
                cloud_info['evidence'].append('waf: AppTrana')
                if args.verbose:
                    print(f"{Fore.YELLOW}[DEBUG]{Style.RESET_ALL} AppTrana WAF detected in server header")
            elif 'cloudflare' in server and cloud_info['provider'] == 'Unknown':
                cloud_info['provider'] = 'Cloudflare'
                cloud_info['cdn'] = 'Cloudflare'
                cloud_info['evidence'].append('server_header')
            elif 'amazons3' in server or 'awselb' in server or 'aws' in server:
                cloud_info['provider'] = 'AWS'
                cloud_info['evidence'].append('server_header')
            elif 'azure' in server:
                cloud_info['provider'] = 'Azure'
                cloud_info['evidence'].append('server_header')
            elif 'imperva' in server or 'incapsula' in server:
                cloud_info['waf'] = 'Imperva/Incapsula'
            
            # Via header (CDN detection)
            via = headers.get('via', '').lower()
            if 'cloudflare' in via:
                cloud_info['cdn'] = 'Cloudflare'
            elif 'fastly' in via:
                cloud_info['cdn'] = 'Fastly'
            elif 'akamai' in via:
                cloud_info['cdn'] = 'Akamai'
            
            # X-headers for cloud detection
            x_amz = any('x-amz' in h.lower() for h in headers.keys())
            if x_amz:
                cloud_info['provider'] = 'AWS'
                cloud_info['evidence'].append('x-amz-headers')
            
            # CloudFront detection
            if 'x-cache' in headers and 'cloudfront' in headers.get('x-cache', '').lower():
                cloud_info['provider'] = 'AWS'
                cloud_info['services'].append('CloudFront')
                cloud_info['cdn'] = 'AWS CloudFront'
            
            # Azure-specific headers
            if 'x-ms-' in str(headers.keys()).lower():
                cloud_info['provider'] = 'Azure'
                cloud_info['evidence'].append('x-ms-headers')
        
        # Check DNS CNAME for cloud patterns
        try:
            ok, ips, cnames = dns_resolve_all(domain, args.timeout)
            
            # Store IP addresses
            if ips:
                cloud_info['ips'] = ips
                
                # IP-based cloud detection (AWS IP ranges)
                for ip_str in ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        
                        # AWS IP Ranges (common ones - 3.x.x.x is AWS Mumbai/Singapore)
                        aws_ranges = [
                            '3.0.0.0/15', '3.2.0.0/15', '3.5.0.0/16', '3.6.0.0/15',  # AWS Asia
                            '13.0.0.0/8', '18.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8',  # AWS Global
                        ]
                        
                        for cidr in aws_ranges:
                            if ip_obj in ipaddress.ip_network(cidr):
                                if cloud_info['provider'] == 'Unknown':
                                    cloud_info['provider'] = 'AWS'
                                cloud_info['evidence'].append(f'ip: {ip_str} (AWS range {cidr})')
                                if ip_str.startswith('3.'):
                                    cloud_info['region'] = 'Asia-Pacific (Mumbai/Singapore)'
                                break
                        
                        # GCP IP Ranges
                        if str(ip_obj).startswith(('34.', '35.')) and cloud_info['provider'] == 'Unknown':
                            cloud_info['provider'] = 'Google Cloud'
                            cloud_info['evidence'].append(f'ip: {ip_str} (GCP range)')
                        
                        # Azure IP Ranges
                        if str(ip_obj).startswith(('20.', '40.', '51.')) and cloud_info['provider'] == 'Unknown':
                            cloud_info['provider'] = 'Azure'
                            cloud_info['evidence'].append(f'ip: {ip_str} (Azure range)')
                    except:
                        pass
            
            if cnames:
                for cname in cnames:
                    cname_lower = cname.lower()
                    
                    # AWS patterns
                    if any(pattern in cname_lower for pattern in ['cloudfront.net', 'amazonaws.com', 'awsglobalaccelerator.com', 'elb.amazonaws.com']):
                        cloud_info['provider'] = 'AWS'
                        cloud_info['evidence'].append(f'cname: {cname}')
                        if 'cloudfront' in cname_lower:
                            cloud_info['cdn'] = 'AWS CloudFront'
                        if 'elb' in cname_lower:
                            cloud_info['services'].append('Elastic Load Balancer')
                    
                    # Azure patterns
                    elif any(pattern in cname_lower for pattern in ['azureedge.net', 'azure.com', 'azurefd.net', 'trafficmanager.net']):
                        cloud_info['provider'] = 'Azure'
                        cloud_info['evidence'].append(f'cname: {cname}')
                        if 'azureedge' in cname_lower:
                            cloud_info['cdn'] = 'Azure CDN'
                    
                    # GCP patterns
                    elif any(pattern in cname_lower for pattern in ['googleusercontent.com', 'googleapis.com', 'ghs.google.com', 'appspot.com']):
                        cloud_info['provider'] = 'Google Cloud'
                        cloud_info['evidence'].append(f'cname: {cname}')
                    
                    # CDN patterns (including Indian CDNs)
                    elif 'cloudflare.net' in cname_lower:
                        cloud_info['cdn'] = 'Cloudflare'
                        cloud_info['evidence'].append(f'cname: {cname}')
                    elif 'fastly.net' in cname_lower:
                        cloud_info['cdn'] = 'Fastly'
                        cloud_info['evidence'].append(f'cname: {cname}')
                    elif 'akamai.net' in cname_lower or 'akamaiedge.net' in cname_lower:
                        cloud_info['cdn'] = 'Akamai'
                        cloud_info['evidence'].append(f'cname: {cname}')
                    elif 'cdn77.org' in cname_lower:
                        cloud_info['cdn'] = 'CDN77'
                        cloud_info['evidence'].append(f'cname: {cname}')
                    # Indian CDN providers
                    elif 'induscdn' in cname_lower or 'indusnet' in cname_lower:
                        cloud_info['cdn'] = 'IndusCDN'
                        cloud_info['evidence'].append(f'cname: {cname}')
                    elif 'tatacdn' in cname_lower:
                        cloud_info['cdn'] = 'Tata CDN'
                        cloud_info['evidence'].append(f'cname: {cname}')
        except:
            pass
        
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[CLOUD]{Style.RESET_ALL} Detection failed: {e}")
    
    return cloud_info

# ---------------------------
# SUBDOMAIN TAKEOVER DETECTION
# ---------------------------
def detect_subdomain_takeover(subdomain, timeout=10):
    """
    Advanced Subdomain Takeover Detection
    Checks for dangling DNS records pointing to unclaimed services
    
    Returns: dict with takeover status, risk level, service, and PoC steps
    """
    takeover_info = {
        'vulnerable': False,
        'risk_level': 'SAFE',
        'service': None,
        'cname': None,
        'indicators': [],
        'poc_steps': [],
        'confidence': 0
    }
    
    # Service Fingerprint Database
    # CNAME patterns and error signatures for 15+ hosting platforms
    TAKEOVER_SIGNATURES = {
        'AWS S3': {
            'cname_patterns': ['.s3.amazonaws.com', '.s3-website', 's3.amazonaws.com'],
            'error_patterns': ['NoSuchBucket', 'The specified bucket does not exist'],
            'http_codes': [404],
            'risk': 'CRITICAL',
            'poc': [
                '1. Create AWS account',
                '2. Create S3 bucket with exact CNAME name',
                '3. Upload index.html with your content',
                '4. Enable static website hosting',
                '5. Verify takeover via subdomain access'
            ]
        },
        'GitHub Pages': {
            'cname_patterns': ['.github.io', 'github.io'],
            'error_patterns': ['There isn\'t a GitHub Pages site here', 'repository not found'],
            'http_codes': [404],
            'risk': 'HIGH',
            'poc': [
                '1. Create GitHub repository matching subdomain',
                '2. Enable GitHub Pages in settings',
                '3. Add CNAME file with subdomain',
                '4. Push index.html to repo',
                '5. Verify takeover'
            ]
        },
        'Heroku': {
            'cname_patterns': ['.herokuapp.com', '.herokudns.com'],
            'error_patterns': ['No such app', 'There\'s nothing here', 'herokucdn.com/error'],
            'http_codes': [404],
            'risk': 'HIGH',
            'poc': [
                '1. Create Heroku account',
                '2. Create app with matching CNAME name',
                '3. Deploy simple web app',
                '4. Add custom domain in settings',
                '5. Verify takeover'
            ]
        },
        'Netlify': {
            'cname_patterns': ['.netlify.com', '.netlify.app'],
            'error_patterns': ['Not Found - Request ID', 'netlify'],
            'http_codes': [404],
            'risk': 'HIGH',
            'poc': [
                '1. Create Netlify account',
                '2. Deploy static site',
                '3. Add custom domain matching subdomain',
                '4. Update DNS if needed',
                '5. Verify takeover'
            ]
        },
        'Azure': {
            'cname_patterns': ['.azurewebsites.net', '.cloudapp.azure.com', '.trafficmanager.net', '.blob.core.windows.net'],
            'error_patterns': ['404 Web Site not found', 'Error 404'],
            'http_codes': [404],
            'risk': 'CRITICAL',
            'poc': [
                '1. Create Azure account',
                '2. Create Web App or Storage with matching name',
                '3. Configure custom domain',
                '4. Deploy content',
                '5. Verify takeover'
            ]
        },
        'Shopify': {
            'cname_patterns': ['.myshopify.com'],
            'error_patterns': ['Only one step left', 'This shop is currently unavailable'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': [
                '1. Create Shopify store',
                '2. Add custom domain in settings',
                '3. Verify DNS points to subdomain',
                '4. Activate domain',
                '5. Verify takeover'
            ]
        },
        'Tumblr': {
            'cname_patterns': ['.tumblr.com'],
            'error_patterns': ['There\'s nothing here', 'Whatever you were looking for'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': [
                '1. Create Tumblr blog',
                '2. Go to Settings > Custom domain',
                '3. Add subdomain',
                '4. Verify DNS',
                '5. Publish content'
            ]
        },
        'WordPress.com': {
            'cname_patterns': ['.wordpress.com'],
            'error_patterns': ['Do you want to register'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': [
                '1. Create WordPress.com site',
                '2. Upgrade to custom domain plan',
                '3. Add subdomain in domain settings',
                '4. Verify takeover'
            ]
        },
        'Pantheon': {
            'cname_patterns': ['.pantheonsite.io', '.pantheon.io'],
            'error_patterns': ['404 error unknown site'],
            'http_codes': [404],
            'risk': 'HIGH',
            'poc': [
                '1. Create Pantheon account',
                '2. Create site',
                '3. Add custom domain',
                '4. Configure DNS',
                '5. Deploy content'
            ]
        },
        'Bitbucket': {
            'cname_patterns': ['.bitbucket.io'],
            'error_patterns': ['Repository not found'],
            'http_codes': [404],
            'risk': 'HIGH',
            'poc': [
                '1. Create Bitbucket repository',
                '2. Enable Bitbucket Pages',
                '3. Add CNAME file',
                '4. Push content',
                '5. Verify takeover'
            ]
        },
        'Fastly': {
            'cname_patterns': ['.fastly.net', '.fastlylb.net'],
            'error_patterns': ['Fastly error: unknown domain'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': [
                '1. Contact Fastly support (requires enterprise)',
                '2. Claim domain in Fastly dashboard',
                '3. Configure service',
                '4. Verify takeover'
            ]
        },
        'Cargo Collective': {
            'cname_patterns': ['.cargocollective.com'],
            'error_patterns': ['404 Not Found'],
            'http_codes': [404],
            'risk': 'LOW',
            'poc': ['Cargo Collective takeover requires manual verification']
        },
        'Feedpress': {
            'cname_patterns': ['.feedpress.me'],
            'error_patterns': ['The feed has not been found'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': ['Create Feedpress account and claim feed']
        },
        'Ghost.io': {
            'cname_patterns': ['.ghost.io'],
            'error_patterns': ['The thing you were looking for is no longer here'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': ['Create Ghost.io blog and add custom domain']
        },
        'HelpScout': {
            'cname_patterns': ['.helpscoutdocs.com'],
            'error_patterns': ['No settings were found for this company'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': ['Create HelpScout account and configure docs site']
        },
        'Readme.io': {
            'cname_patterns': ['.readme.io'],
            'error_patterns': ['Project doesnt exist'],
            'http_codes': [404],
            'risk': 'MEDIUM',
            'poc': ['Create Readme.io project with custom domain']
        }
    }
    
    try:
        # Step 1: DNS Resolution - Check for CNAME records
        import subprocess
        cname_result = subprocess.run(['dig', '+short', 'CNAME', subdomain], 
                                     capture_output=True, text=True, timeout=timeout)
        
        if cname_result.returncode == 0 and cname_result.stdout.strip():
            cname = cname_result.stdout.strip().lower()
            takeover_info['cname'] = cname
            
            # Step 2: Check CNAME against service fingerprints
            for service_name, signatures in TAKEOVER_SIGNATURES.items():
                for pattern in signatures['cname_patterns']:
                    if pattern in cname:
                        takeover_info['service'] = service_name
                        takeover_info['indicators'].append(f'CNAME points to {service_name}: {cname}')
                        
                        # Step 3: HTTP Request to check for error pages
                        try:
                            import requests as req_lib
                            response = req_lib.get(f'https://{subdomain}', 
                                                  timeout=timeout, 
                                                  verify=False, 
                                                  allow_redirects=True)
                            
                            response_text = response.text
                            status_code = response.status_code
                            
                            # Check for takeover indicators in response
                            confidence = 0
                            
                            # Check HTTP status code
                            if status_code in signatures.get('http_codes', []):
                                confidence += 30
                                takeover_info['indicators'].append(f'HTTP {status_code} detected')
                            
                            # Check for error patterns in response
                            for error_pattern in signatures.get('error_patterns', []):
                                if error_pattern.lower() in response_text.lower():
                                    confidence += 40
                                    takeover_info['indicators'].append(f'Error signature found: "{error_pattern}"')
                                    break
                            
                            # Step 4: DNS A record check (if no HTTP response, check if DNS resolves)
                            if confidence == 0:
                                # CNAME exists but no error page - check if A record exists
                                a_result = subprocess.run(['dig', '+short', 'A', subdomain],
                                                        capture_output=True, text=True, timeout=timeout)
                                if a_result.returncode == 0:
                                    ips = a_result.stdout.strip()
                                    if not ips:
                                        confidence += 30
                                        takeover_info['indicators'].append('CNAME exists but no A record (dangling DNS)')
                            
                            # Step 5: Calculate risk and vulnerability status
                            takeover_info['confidence'] = min(confidence, 100)
                            
                            if confidence >= 70:
                                takeover_info['vulnerable'] = True
                                takeover_info['risk_level'] = signatures['risk']
                                takeover_info['poc_steps'] = signatures.get('poc', [])
                            elif confidence >= 40:
                                takeover_info['risk_level'] = 'POSSIBLE'
                                takeover_info['poc_steps'] = signatures.get('poc', [])
                            elif confidence >= 20:
                                takeover_info['risk_level'] = 'LOW'
                            
                        except req_lib.exceptions.RequestException as e:
                            # If HTTP request fails, might still be vulnerable
                            takeover_info['indicators'].append(f'HTTP request failed: {str(e)[:100]}')
                            takeover_info['risk_level'] = 'POSSIBLE'
                            takeover_info['confidence'] = 30
                        
                        break  # Found matching service, exit loop
                
                if takeover_info['service']:
                    break  # Service identified, exit outer loop
        
        else:
            # No CNAME found
            takeover_info['indicators'].append('No CNAME record found')
    
    except Exception as e:
        takeover_info['indicators'].append(f'Detection error: {str(e)}')
    
    return takeover_info

def find_cloud_storage_buckets(domain):
    """
    Enumerate potential cloud storage buckets
    AWS S3, Azure Blob, GCP Storage
    """
    buckets_found = []
    
    # Generate bucket name variations
    base_names = [
        domain,
        domain.replace('.', '-'),
        domain.replace('.', ''),
        domain.split('.')[0],
        f"{domain.split('.')[0]}-assets",
        f"{domain.split('.')[0]}-backup",
        f"{domain.split('.')[0]}-data"
    ]
    
    print(f"{Fore.CYAN}[CLOUD-STORAGE]{Style.RESET_ALL} Checking for exposed cloud storage...")
    
    for base in base_names:
        # AWS S3 patterns
        s3_urls = [
            f"https://{base}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{base}",
            f"https://{base}.s3-website-us-east-1.amazonaws.com"
        ]
        
        for s3_url in s3_urls:
            try:
                r = safe_request_get(s3_url, timeout=3, max_retries=1)
                if r and r.status_code in [200, 403]:
                    buckets_found.append({
                        'type': 'AWS S3',
                        'url': s3_url,
                        'bucket_name': base,
                        'status': r.status_code,
                        'public': r.status_code == 200,
                        'severity': 'CRITICAL' if r.status_code == 200 else 'INFO'
                    })
                    print(f"{Fore.GREEN if r.status_code == 200 else Fore.YELLOW}[S3]{Style.RESET_ALL} Found: {s3_url} (Status: {r.status_code})")
            except:
                pass
        
        # Azure Blob Storage patterns
        azure_urls = [
            f"https://{base}.blob.core.windows.net",
            f"https://{base.replace('.', '')}.blob.core.windows.net"
        ]
        
        for azure_url in azure_urls:
            try:
                r = safe_request_get(azure_url, timeout=3, max_retries=1)
                if r and r.status_code in [200, 400, 403]:
                    buckets_found.append({
                        'type': 'Azure Blob',
                        'url': azure_url,
                        'container_name': base,
                        'status': r.status_code,
                        'public': r.status_code == 200,
                        'severity': 'CRITICAL' if r.status_code == 200 else 'INFO'
                    })
                    print(f"{Fore.GREEN if r.status_code == 200 else Fore.YELLOW}[AZURE]{Style.RESET_ALL} Found: {azure_url} (Status: {r.status_code})")
            except:
                pass
        
        # GCP Storage patterns
        gcp_urls = [
            f"https://storage.googleapis.com/{base}",
            f"https://{base}.storage.googleapis.com"
        ]
        
        for gcp_url in gcp_urls:
            try:
                r = safe_request_get(gcp_url, timeout=3, max_retries=1)
                if r and r.status_code in [200, 403]:
                    buckets_found.append({
                        'type': 'GCP Storage',
                        'url': gcp_url,
                        'bucket_name': base,
                        'status': r.status_code,
                        'public': r.status_code == 200,
                        'severity': 'CRITICAL' if r.status_code == 200 else 'INFO'
                    })
                    print(f"{Fore.GREEN if r.status_code == 200 else Fore.YELLOW}[GCP]{Style.RESET_ALL} Found: {gcp_url} (Status: {r.status_code})")
            except:
                pass
    
    # Print summary
    if buckets_found:
        public_count = len([b for b in buckets_found if b['public']])
        print(f"\n{Fore.GREEN}[STORAGE-SUMMARY]{Style.RESET_ALL} Found {len(buckets_found)} cloud storage buckets")
        if public_count > 0:
            print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} {public_count} PUBLIC buckets found (potential data exposure)!")
    else:
        print(f"\n{Fore.YELLOW}[STORAGE-SUMMARY]{Style.RESET_ALL} No cloud storage buckets discovered")
    
    return buckets_found

# ---------------------------
# AI-POWERED CLOUD VULNERABILITY DETECTION
# ---------------------------
def ai_cloud_vulnerability_scan(domain, cloud_info):
    """
    AI-powered cloud-specific vulnerability detection
    Based on detected provider, checks for:
    - AWS: Exposed credentials, metadata endpoints, S3 misconfigs
    - Azure: Storage keys, metadata endpoints, blob misconfigs  
    - GCP: Service account keys, metadata endpoints, storage misconfigs
    """
    vulnerabilities = []
    
    provider = cloud_info.get('provider', 'Unknown')
    ips = cloud_info.get('ips', [])
    
    print(f"{Fore.CYAN}[AI-CLOUD-VULN]{Style.RESET_ALL} Running AI-powered {provider} vulnerability scan...")
    
    # AWS-Specific Vulnerability Checks
    if provider == 'AWS':
        print(f"{Fore.CYAN}[AWS-SCAN]{Style.RESET_ALL} Checking AWS-specific vulnerabilities...")
        
        # 1. AWS Metadata Endpoint (SSRF/IMDSv1)
        metadata_endpoints = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/',
        ]
        
        for endpoint in metadata_endpoints:
            try:
                # Note: This would only work if we can make requests FROM the target server
                # In real pentest, this is checked via SSRF vulnerabilities
                print(f"{Fore.YELLOW}[AWS-METADATA]{Style.RESET_ALL} Metadata endpoint check: {endpoint}")
                vulnerabilities.append({
                    'type': 'AWS Metadata Endpoint',
                    'endpoint': endpoint,
                    'severity': 'HIGH',
                    'description': 'AWS metadata endpoints may expose IAM credentials if SSRF exists',
                    'recommendation': 'Ensure IMDSv2 is enforced and check for SSRF vulnerabilities'
                })
            except:
                pass
        
        # 2. Check for exposed AWS credentials in common locations
        credential_paths = [
            '/.aws/credentials',
            '/.aws/config',
            '/aws-credentials',
            '/.env',
            '/config.json',
            '/secrets.json',
        ]
        
        for path in credential_paths:
            try:
                url = f"https://{domain}{path}"
                r = safe_request_get(url, timeout=3, max_retries=1)
                if r and r.status_code == 200:
                    content = r.text.lower()
                    if any(keyword in content for keyword in ['aws_access_key_id', 'aws_secret_access_key', 'access_key']):
                        vulnerabilities.append({
                            'type': 'Exposed AWS Credentials',
                            'url': url,
                            'severity': 'CRITICAL',
                            'description': f'AWS credentials exposed at {url}',
                            'recommendation': 'Immediately rotate credentials and restrict file access'
                        })
                        print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} Exposed AWS credentials found: {url}")
            except:
                pass
        
        # 3. Check for AWS S3 bucket enumeration via DNS
        print(f"{Fore.CYAN}[AWS-S3]{Style.RESET_ALL} Checking S3 bucket permissions...")
        
        # 4. Check for exposed AWS SDK configs
        sdk_paths = [
            '/aws-exports.js',
            '/aws-config.json',
            '/amplify-config.json',
        ]
        
        for path in sdk_paths:
            try:
                url = f"https://{domain}{path}"
                r = safe_request_get(url, timeout=3, max_retries=1)
                if r and r.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Exposed AWS SDK Config',
                        'url': url,
                        'severity': 'MEDIUM',
                        'description': f'AWS SDK configuration exposed at {url}',
                        'recommendation': 'Review exposed configuration for sensitive data'
                    })
                    print(f"{Fore.YELLOW}[AWS-CONFIG]{Style.RESET_ALL} Exposed config: {url}")
            except:
                pass
    
    # Azure-Specific Vulnerability Checks
    elif provider == 'Azure':
        print(f"{Fore.CYAN}[AZURE-SCAN]{Style.RESET_ALL} Checking Azure-specific vulnerabilities...")
        
        # 1. Azure Metadata Endpoint
        metadata_endpoints = [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token',
        ]
        
        for endpoint in metadata_endpoints:
            vulnerabilities.append({
                'type': 'Azure Metadata Endpoint',
                'endpoint': endpoint,
                'severity': 'HIGH',
                'description': 'Azure metadata endpoints may expose managed identity tokens if SSRF exists',
                'recommendation': 'Check for SSRF vulnerabilities and ensure metadata access is restricted'
            })
        
        # 2. Check for exposed Azure Storage keys
        storage_paths = [
            '/.env',
            '/appsettings.json',
            '/web.config',
            '/azure-storage.json',
        ]
        
        for path in storage_paths:
            try:
                url = f"https://{domain}{path}"
                r = safe_request_get(url, timeout=3, max_retries=1)
                if r and r.status_code == 200:
                    content = r.text.lower()
                    if any(keyword in content for keyword in ['accountkey', 'storageaccountkey', 'defaultendpointsprotocol']):
                        vulnerabilities.append({
                            'type': 'Exposed Azure Storage Key',
                            'url': url,
                            'severity': 'CRITICAL',
                            'description': f'Azure storage keys exposed at {url}',
                            'recommendation': 'Immediately rotate storage keys and restrict file access'
                        })
                        print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} Exposed Azure storage keys: {url}")
            except:
                pass
    
    # GCP-Specific Vulnerability Checks
    elif provider == 'Google Cloud' or provider == 'GCP':
        print(f"{Fore.CYAN}[GCP-SCAN]{Style.RESET_ALL} Checking GCP-specific vulnerabilities...")
        
        # 1. GCP Metadata Endpoint
        metadata_endpoints = [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        ]
        
        for endpoint in metadata_endpoints:
            vulnerabilities.append({
                'type': 'GCP Metadata Endpoint',
                'endpoint': endpoint,
                'severity': 'HIGH',
                'description': 'GCP metadata endpoints may expose service account tokens if SSRF exists',
                'recommendation': 'Check for SSRF vulnerabilities and ensure metadata access requires headers'
            })
        
        # 2. Check for exposed GCP service account keys
        key_paths = [
            '/.env',
            '/service-account.json',
            '/gcp-key.json',
            '/credentials.json',
            '/firebase-adminsdk.json',
        ]
        
        for path in key_paths:
            try:
                url = f"https://{domain}{path}"
                r = safe_request_get(url, timeout=3, max_retries=1)
                if r and r.status_code == 200:
                    content = r.text.lower()
                    if any(keyword in content for keyword in ['private_key', 'service_account', 'project_id', 'client_email']):
                        vulnerabilities.append({
                            'type': 'Exposed GCP Service Account Key',
                            'url': url,
                            'severity': 'CRITICAL',
                            'description': f'GCP service account key exposed at {url}',
                            'recommendation': 'Immediately revoke and rotate service account keys'
                        })
                        print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} Exposed GCP keys: {url}")
            except:
                pass
    
    # AI-Enhanced Analysis
    if ai_system.ollama_available and len(vulnerabilities) > 0:
        print(f"{Fore.CYAN}[AI-ANALYSIS]{Style.RESET_ALL} Using AI to analyze vulnerability patterns...")
        
        # Prepare context for AI
        vuln_summary = f"Cloud Provider: {provider}\n"
        vuln_summary += f"Vulnerabilities Found: {len(vulnerabilities)}\n"
        vuln_summary += "\n".join([f"- {v['type']}: {v.get('severity', 'UNKNOWN')}" for v in vulnerabilities[:5]])
        
        ai_prompt = f"""Analyze these cloud security findings and provide exploitation recommendations:

{vuln_summary}

Provide:
1. Attack vector prioritization
2. Potential impact
3. Recommended exploit chain
4. Mitigation priority

Be concise and technical."""
        
        try:
            ai_analysis = ai_system.query_ollama(ai_prompt)
            if ai_analysis:
                vulnerabilities.append({
                    'type': 'AI Security Analysis',
                    'analysis': ai_analysis,
                    'severity': 'INFO',
                    'description': 'AI-generated security analysis and recommendations'
                })
                print(f"{Fore.GREEN}[AI-ANALYSIS]{Style.RESET_ALL} AI analysis completed")
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} AI analysis failed: {e}")
    
    # Summary
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
    medium_count = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
    
    print(f"\n{Fore.CYAN}[VULN-SUMMARY]{Style.RESET_ALL} Cloud Vulnerability Scan Complete")
    print(f"  • Total Findings: {len(vulnerabilities)}")
    if critical_count > 0:
        print(f"  • {Fore.RED}CRITICAL{Style.RESET_ALL}: {critical_count}")
    if high_count > 0:
        print(f"  • {Fore.YELLOW}HIGH{Style.RESET_ALL}: {high_count}")
    if medium_count > 0:
        print(f"  • {Fore.CYAN}MEDIUM{Style.RESET_ALL}: {medium_count}")
    
    # Show vulnerability details in verbose mode
    if args.verbose and vulnerabilities:
        print(f"\n{Fore.CYAN}[VULN-DETAILS]{Style.RESET_ALL} Detailed Findings:")
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = Fore.RED if vuln.get('severity') == 'CRITICAL' else (
                Fore.YELLOW if vuln.get('severity') == 'HIGH' else Fore.CYAN
            )
            print(f"\n  {i}. [{severity_color}{vuln.get('severity')}{Style.RESET_ALL}] {vuln.get('type')}")
            if vuln.get('url'):
                print(f"     URL: {vuln.get('url')}")
            if vuln.get('endpoint'):
                print(f"     Endpoint: {vuln.get('endpoint')}")
            if vuln.get('description'):
                print(f"     Description: {vuln.get('description')}")
            if vuln.get('recommendation'):
                print(f"     {Fore.GREEN}Recommendation{Style.RESET_ALL}: {vuln.get('recommendation')}")
            if vuln.get('analysis'):
                print(f"     {Fore.CYAN}AI Analysis{Style.RESET_ALL}:")
                # Print first 300 chars of AI analysis
                analysis_text = vuln.get('analysis', '')[:300]
                for line in analysis_text.split('\n'):
                    if line.strip():
                        print(f"       {line.strip()}")
    
    return vulnerabilities

# ---------------------------
# API ENDPOINT DISCOVERY
# ---------------------------
def discover_api_endpoints(domain, base_url):
    """
    Discover API endpoints through multiple methods:
    - Common API paths
    - OpenAPI/Swagger documentation
    - GraphQL endpoints
    - REST API patterns
    """
    api_discoveries = {
        'rest_apis': [],
        'graphql': [],
        'swagger_docs': [],
        'api_gateways': [],
        'grpc': []
    }
    
    print(f"{Fore.CYAN}[API-DISCOVERY]{Style.RESET_ALL} Scanning for API endpoints...")
    
    # First, check if the base_url itself is an API endpoint (e.g., direct GraphQL URL)
    if 'graphql' in base_url.lower() or '/api' in base_url.lower():
        try:
            # Try GraphQL introspection if URL contains 'graphql'
            if 'graphql' in base_url.lower():
                introspection_test = requests.post(
                    base_url,
                    json={'query': '{ __schema { queryType { name } } }'},
                    headers={'Content-Type': 'application/json'},
                    timeout=5,
                    verify=False
                )
                if introspection_test.status_code == 200 and 'data' in introspection_test.text:
                    api_discoveries['graphql'].append({
                        'url': base_url,
                        'status': 200,
                        'introspection_enabled': True
                    })
                    print(f"{Fore.GREEN}[GRAPHQL]{Style.RESET_ALL} Found GraphQL endpoint: {base_url}")
        except Exception as e:
            if args.verbose:
                print(f"{Fore.YELLOW}[API]{Style.RESET_ALL} Base URL check failed: {e}")
    
    # Common API paths
    api_paths = [
        '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
        '/v1', '/v2', '/v3', '/v1/', '/v2/', '/v3/',
        '/rest', '/rest/', '/rest/api', '/rest/api/v1',
        '/graphql', '/gql', '/graphql/', '/api/graphql',
        '/swagger', '/swagger.json', '/swagger.yaml', '/swagger/v1/swagger.json',
        '/openapi.json', '/openapi.yaml', '/openapi/v3/openapi.json',
        '/api-docs', '/api/docs', '/api/documentation',
        '/redoc', '/rapidoc', '/docs',
        '/gateway', '/api-gateway',
        '/.well-known/openapi.json'
    ]
    
    with tqdm(total=len(api_paths), desc="API Paths", unit="path") as pbar:
        for path in api_paths:
            url = f"{base_url}{path}"
            try:
                r = safe_request_get(url, timeout=5, max_retries=1)
                
                if r and r.status_code == 200:
                    content_type = r.headers.get('content-type', '').lower()
                    content = r.text[:10000]  # First 10KB
                    
                    # Detect API type
                    api_type = None
                    endpoints = []
                    
                    # GraphQL detection
                    if 'graphql' in path.lower() or 'graphql' in content.lower() or '__schema' in content:
                        api_type = 'GraphQL'
                        api_discoveries['graphql'].append({
                            'url': url,
                            'status': r.status_code,
                            'introspection_enabled': '__schema' in content or 'IntrospectionQuery' in content
                        })
                        print(f"{Fore.GREEN}[GRAPHQL]{Style.RESET_ALL} Found GraphQL endpoint: {url}")
                    
                    # Swagger/OpenAPI detection
                    elif any(keyword in content.lower() for keyword in ['swagger', 'openapi', '"swagger":', '"openapi":']):
                        api_type = 'Swagger/OpenAPI'
                        try:
                            import json
                            api_doc = json.loads(content)
                            
                            # Extract endpoints from OpenAPI spec
                            if 'paths' in api_doc:
                                endpoints = list(api_doc['paths'].keys())
                            
                            api_discoveries['swagger_docs'].append({
                                'url': url,
                                'version': api_doc.get('openapi') or api_doc.get('swagger'),
                                'title': api_doc.get('info', {}).get('title'),
                                'endpoints_count': len(endpoints),
                                'endpoints': endpoints[:20]  # First 20
                            })
                            print(f"{Fore.GREEN}[OPENAPI]{Style.RESET_ALL} Found OpenAPI docs: {url} ({len(endpoints)} endpoints)")
                        except:
                            api_discoveries['swagger_docs'].append({'url': url, 'parsable': False})
                    
                    # REST API detection
                    elif 'application/json' in content_type or path.startswith('/api'):
                        api_type = 'REST API'
                        api_discoveries['rest_apis'].append({
                            'url': url,
                            'status': r.status_code,
                            'content_type': content_type
                        })
                        print(f"{Fore.GREEN}[REST]{Style.RESET_ALL} Found REST API: {url}")
                
                pbar.update(1)
                
            except Exception as e:
                pbar.update(1)
                if args.verbose:
                    print(f"{Fore.YELLOW}[API]{Style.RESET_ALL} {path} check failed: {e}")
    
    # Print summary
    total_found = (len(api_discoveries['rest_apis']) + 
                   len(api_discoveries['graphql']) + 
                   len(api_discoveries['swagger_docs']))
    
    if total_found > 0:
        print(f"\n{Fore.GREEN}[API-SUMMARY]{Style.RESET_ALL} Found {total_found} API endpoints:")
        if api_discoveries['rest_apis']:
            print(f"  {Fore.CYAN}REST APIs:{Style.RESET_ALL} {len(api_discoveries['rest_apis'])}")
        if api_discoveries['graphql']:
            print(f"  {Fore.CYAN}GraphQL:{Style.RESET_ALL} {len(api_discoveries['graphql'])}")
        if api_discoveries['swagger_docs']:
            print(f"  {Fore.CYAN}OpenAPI/Swagger:{Style.RESET_ALL} {len(api_discoveries['swagger_docs'])}")
    else:
        print(f"\n{Fore.YELLOW}[API-SUMMARY]{Style.RESET_ALL} No API endpoints discovered")
    
    return api_discoveries

# ---------------------------
# CONTAINER & KUBERNETES DETECTION
# ---------------------------
def detect_container_infrastructure(domain):
    """
    Detect exposed container and orchestration platforms:
    - Docker API
    - Kubernetes Dashboard/API
    - Docker Registry
    - Portainer, Rancher
    """
    container_findings = []
    
    print(f"{Fore.CYAN}[CONTAINER]{Style.RESET_ALL} Checking for container infrastructure...")
    
    # Define container/orchestration endpoints
    endpoints_to_check = [
        # Docker
        {'port': 2375, 'path': '/version', 'name': 'Docker API (Insecure)', 'severity': 'CRITICAL'},
        {'port': 2376, 'path': '/version', 'name': 'Docker API (TLS)', 'severity': 'HIGH'},
        {'port': 5000, 'path': '/v2/', 'name': 'Docker Registry', 'severity': 'MEDIUM'},
        {'port': 5000, 'path': '/v2/_catalog', 'name': 'Docker Registry Catalog', 'severity': 'HIGH'},
        
        # Kubernetes
        {'port': 6443, 'path': '/api', 'name': 'Kubernetes API Server', 'severity': 'CRITICAL'},
        {'port': 8001, 'path': '/api', 'name': 'Kubernetes API Proxy', 'severity': 'CRITICAL'},
        {'port': 10250, 'path': '/pods', 'name': 'Kubelet API', 'severity': 'CRITICAL'},
        {'port': 10255, 'path': '/pods', 'name': 'Kubelet Read-only', 'severity': 'HIGH'},
        {'port': 443, 'path': '/api/v1', 'name': 'Kubernetes API (443)', 'severity': 'HIGH'},
        
        # Management UIs
        {'port': 9000, 'path': '/', 'name': 'Portainer', 'severity': 'HIGH'},
        {'port': 9000, 'path': '/api/status', 'name': 'Portainer API', 'severity': 'HIGH'},
        {'port': 8080, 'path': '/', 'name': 'Kubernetes Dashboard (8080)', 'severity': 'HIGH'},
        {'port': 8443, 'path': '/', 'name': 'Rancher', 'severity': 'HIGH'},
        {'port': 30000, 'path': '/', 'name': 'K8s NodePort Range', 'severity': 'MEDIUM'}
    ]
    
    with tqdm(total=len(endpoints_to_check), desc="Container Checks", unit="check") as pbar:
        for endpoint in endpoints_to_check:
            url = f"https://{domain}:{endpoint['port']}{endpoint['path']}"
            
            try:
                # Try HTTPS first
                r = safe_request_get(url, timeout=3, max_retries=1)
                
                if r and r.status_code in [200, 401, 403]:
                    container_findings.append({
                        'type': endpoint['name'],
                        'url': url,
                        'port': endpoint['port'],
                        'status': r.status_code,
                        'severity': endpoint['severity'],
                        'exposed': r.status_code == 200,
                        'requires_auth': r.status_code in [401, 403]
                    })
                    
                    severity_color = Fore.RED if endpoint['severity'] == 'CRITICAL' else Fore.YELLOW
                    print(f"{severity_color}[{endpoint['severity']}]{Style.RESET_ALL} {endpoint['name']}: {url} (Status: {r.status_code})")
            except:
                # Try HTTP if HTTPS fails
                try:
                    url_http = url.replace('https://', 'http://')
                    r = safe_request_get(url_http, timeout=3, max_retries=1)
                    
                    if r and r.status_code in [200, 401, 403]:
                        container_findings.append({
                            'type': endpoint['name'],
                            'url': url_http,
                            'port': endpoint['port'],
                            'status': r.status_code,
                            'severity': endpoint['severity'],
                            'exposed': r.status_code == 200,
                            'requires_auth': r.status_code in [401, 403]
                        })
                        
                        severity_color = Fore.RED if endpoint['severity'] == 'CRITICAL' else Fore.YELLOW
                        print(f"{severity_color}[{endpoint['severity']}]{Style.RESET_ALL} {endpoint['name']}: {url_http} (Status: {r.status_code})")
                except:
                    pass
            
            pbar.update(1)
    
    # Print summary
    if container_findings:
        critical_count = len([c for c in container_findings if c['severity'] == 'CRITICAL' and c['exposed']])
        high_count = len([c for c in container_findings if c['severity'] == 'HIGH' and c['exposed']])
        
        print(f"\n{Fore.GREEN}[CONTAINER-SUMMARY]{Style.RESET_ALL} Found {len(container_findings)} container/orchestration endpoints")
        if critical_count > 0:
            print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} {critical_count} critical exposures detected!")
        if high_count > 0:
            print(f"{Fore.YELLOW}[HIGH]{Style.RESET_ALL} {high_count} high-risk exposures detected")
    else:
        print(f"\n{Fore.YELLOW}[CONTAINER-SUMMARY]{Style.RESET_ALL} No container infrastructure detected")
    
    return container_findings

# ---------------------------
# ENHANCED GRAPHQL INTROSPECTION
# ---------------------------
def graphql_introspection(endpoint_url):
    """
    Perform comprehensive GraphQL introspection
    Extract: Full schema, types, queries, mutations, sensitive fields
    """
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              name
              description
              type {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
            type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            name
            description
            type {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
          interfaces {
            kind
            name
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            kind
            name
          }
        }
        directives {
          name
          description
          locations
          args {
            name
            description
          }
        }
      }
    }
    """
    
    print(f"{Fore.CYAN}[GRAPHQL]{Style.RESET_ALL} Performing introspection on {endpoint_url}...")
    
    try:
        r = requests.post(
            endpoint_url,
            json={'query': introspection_query},
            headers={'Content-Type': 'application/json'},
            timeout=15,
            verify=False
        )
        
        if r.status_code == 200:
            schema_data = r.json()
            
            if 'data' in schema_data and '__schema' in schema_data['data']:
                schema = schema_data['data']['__schema']
                
                # Extract queries and mutations
                queries = []
                mutations = []
                subscriptions = []
                sensitive_fields = []
                
                # Sensitive keywords to look for
                sensitive_keywords = [
                    'password', 'token', 'secret', 'api_key', 'apikey',
                    'credit_card', 'creditcard', 'ssn', 'social_security',
                    'private', 'confidential', 'internal', 'admin',
                    'auth', 'session', 'cookie', 'jwt', 'bearer'
                ]
                
                for type_def in schema['types']:
                    if type_def['name'].startswith('__'):
                        continue  # Skip introspection types
                    
                    # Check if this is Query type
                    if schema['queryType'] and type_def['name'] == schema['queryType']['name']:
                        if type_def.get('fields'):
                            queries = [{'name': f['name'], 'description': f.get('description')} 
                                      for f in type_def['fields']]
                    
                    # Check if this is Mutation type
                    if schema.get('mutationType') and type_def['name'] == schema['mutationType']['name']:
                        if type_def.get('fields'):
                            mutations = [{'name': f['name'], 'description': f.get('description')} 
                                        for f in type_def['fields']]
                    
                    # Check for sensitive fields
                    if type_def.get('fields'):
                        for field in type_def['fields']:
                            field_name_lower = field['name'].lower()
                            if any(keyword in field_name_lower for keyword in sensitive_keywords):
                                sensitive_fields.append({
                                    'type': type_def['name'],
                                    'field': field['name'],
                                    'description': field.get('description'),
                                    'severity': 'HIGH' if 'password' in field_name_lower or 'secret' in field_name_lower else 'MEDIUM'
                                })
                
                result = {
                    'introspection_enabled': True,
                    'queries_count': len(queries),
                    'mutations_count': len(mutations),
                    'queries': queries[:50],  # First 50
                    'mutations': mutations[:50],  # First 50
                    'sensitive_fields_count': len(sensitive_fields),
                    'sensitive_fields': sensitive_fields,
                    'types_count': len([t for t in schema['types'] if not t['name'].startswith('__')]),
                    'has_subscriptions': schema.get('subscriptionType') is not None
                }
                
                # Print findings
                print(f"{Fore.GREEN}[GRAPHQL]{Style.RESET_ALL} Introspection successful!")
                print(f"  - Queries: {len(queries)}")
                print(f"  - Mutations: {len(mutations)}")
                print(f"  - Types: {result['types_count']}")
                
                if sensitive_fields:
                    print(f"{Fore.RED}[GRAPHQL]{Style.RESET_ALL} Found {len(sensitive_fields)} sensitive fields:")
                    for sf in sensitive_fields[:10]:
                        print(f"    - {sf['type']}.{sf['field']} ({sf['severity']})")
                
                return result
            else:
                return {'introspection_enabled': False, 'error': 'Introspection disabled or malformed response'}
        
        else:
            return {'introspection_enabled': False, 'error': f'HTTP {r.status_code}'}
    
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[GRAPHQL]{Style.RESET_ALL} Introspection failed: {e}")
        return {'introspection_enabled': False, 'error': str(e)}

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
    
    # Subdomain takeover checks (LEGACY - Uses new detect_subdomain_takeover)
    if args.takeover:
        print(f"{Fore.CYAN}[TAKEOVER]{Style.RESET_ALL} Checking for subdomain takeovers...")
        for subdomain in all_targets:
            takeover_info = detect_subdomain_takeover(subdomain)
            if takeover_info['vulnerable'] or takeover_info['risk_level'] in ['CRITICAL', 'HIGH', 'POSSIBLE']:
                results["takeovers"][subdomain] = {
                    "type": "subdomain_takeover",
                    "severity": takeover_info['risk_level'],
                    "description": f"Potential {takeover_info['service']} takeover" if takeover_info['service'] else "Potential takeover",
                    "evidence": f"CNAME: {takeover_info['cname']}" if takeover_info['cname'] else "No CNAME",
                    "confidence": takeover_info['confidence']
                }
                print(f"{Fore.RED}[TAKEOVER]{Style.RESET_ALL} {subdomain}: {takeover_info['service']} ({takeover_info['risk_level']})")
    
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
def js_reconnaissance(url):
    """Enhanced JavaScript reconnaissance - uses JSRecon class"""
    print(f"{Fore.CYAN}[PHASE 4.25]{Style.RESET_ALL} JavaScript Reconnaissance")
    
    try:
        # Initialize JSRecon with enhanced capabilities
        jsrecon = JSRecon()
        
        # Use the improved analyze_js method
        results = jsrecon.analyze_js(url)
        
        # Export results if requested (even if results dict is None, jsrecon object has data)
        if args.csv_output:
            jsrecon.export_csv(args.csv_output)
        
        if args.html_output:
            jsrecon.export_html(args.html_output, url)
        
        # Also support --json-output for backwards compatibility
        if args.json_output and args.jsrecon:
            jsrecon.export_json(args.json_output, url)
        
        return results if results else None
            
    except Exception as e:
        print(f"{Fore.RED}[JS-RECON]{Style.RESET_ALL} Failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return None
        if args.verbose:
            import traceback
            traceback.print_exc()
        return None

def js_reconnaissance_OLD_BACKUP(url):
    """OLD VERSION - BACKUP"""
    print(f"{Fore.CYAN}[JS-RECON]{Style.RESET_ALL} Analyzing JavaScript files and frameworks from {url}")
    
    try:
        # Initialize JSRecon with enhanced capabilities
        jsrecon = JSRecon()
        
        # Make initial request to get JavaScript files
        response = requests.get(url, timeout=args.timeout, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # First detect frameworks from main page
            jsrecon._detect_frameworks(response.text, response.headers)
            
            # Find and analyze script tags
            scripts = []
            
            # External scripts
            for script in soup.find_all('script', src=True):
                src = script['src']
                if src.startswith('//'):
                    src = 'https:' + src
                elif not src.startswith(('http://', 'https://')):
                    src = urljoin(url, src)
                scripts.append(src)
                
            # Inline scripts analysis
            for script in soup.find_all('script'):
                if script.string:
                    jsrecon._extract_functions(script.string)
                    jsrecon._find_ajax_calls(script.string)
                    jsrecon._extract_endpoints(script.string, url)
                    jsrecon._scan_sensitive_data(script.string)
            
            # Process discovered scripts
            if scripts:
                print(f"{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Analyzing {len(scripts)} JavaScript files")
                for script in scripts:
                    try:
                        r = requests.get(script, timeout=args.timeout, verify=False)
                        if r.status_code == 200:
                            print(f"{Fore.CYAN}[JS-FILE]{Style.RESET_ALL} Analyzing: {script}")
                            jsrecon.js_files.add(script)
                            
                            # Comprehensive analysis of each JS file
                            content = r.text
                            jsrecon._detect_frameworks(content, r.headers)
                            jsrecon._extract_functions(content)
                            jsrecon._find_ajax_calls(content)
                            jsrecon._extract_endpoints(content, script)
                            jsrecon._scan_sensitive_data(content)
                            jsrecon._find_imports(content, script)
                            
                    except Exception as e:
                        if args.verbose:
                            print(f"{Fore.YELLOW}[JS-RECON]{Style.RESET_ALL} Failed to analyze {script}: {e}")
            
            # Display findings
            
            # Framework Detection
            if jsrecon.frameworks:
                print(f"\n{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Detected Frameworks:")
                for framework, version in jsrecon.frameworks.items():
                    print(f"{Fore.CYAN}[FRAMEWORK]{Style.RESET_ALL} {framework} v{version}")
            
            # JavaScript Functions
            if jsrecon.functions:
                print(f"\n{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Key Functions Found:")
                for func in jsrecon.functions:
                    print(f"{Fore.CYAN}[FUNCTION]{Style.RESET_ALL} {func}")
            
            # Event Handlers
            if jsrecon.event_handlers:
                print(f"\n{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} Event Handlers:")
                for handler in jsrecon.event_handlers:
                    print(f"{Fore.CYAN}[EVENT]{Style.RESET_ALL} {handler}")
            
            # AJAX and WebSocket Calls
            if jsrecon.ajax_calls:
                print(f"\n{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} AJAX Calls Found:")
                for call in jsrecon.ajax_calls:
                    print(f"{Fore.CYAN}[AJAX]{Style.RESET_ALL} {call}")
            
            if jsrecon.websockets:
                print(f"\n{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} WebSocket Connections:")
                for ws in jsrecon.websockets:
                    print(f"{Fore.CYAN}[WEBSOCKET]{Style.RESET_ALL} {ws}")
            
            # API Endpoints
            if jsrecon.api_patterns:
                print(f"\n{Fore.GREEN}[JS-RECON]{Style.RESET_ALL} API Endpoints Found:")
                for endpoint in jsrecon.api_patterns:
                    print(f"{Fore.CYAN}[API]{Style.RESET_ALL} {endpoint}")
            
            # Sensitive Information
            if jsrecon.secrets:
                print(f"\n{Fore.RED}[JS-RECON]{Style.RESET_ALL} Sensitive Information Found:")
                for secret in jsrecon.secrets:
                    print(f"{Fore.RED}[SECRET]{Style.RESET_ALL} {secret}")
            
            return {
                'frameworks': jsrecon.frameworks,
                'functions': list(jsrecon.functions),
                'event_handlers': list(jsrecon.event_handlers),
                'ajax_calls': list(jsrecon.ajax_calls),
                'websockets': list(jsrecon.websockets),
                'endpoints': list(jsrecon.discovered_endpoints),
                'api_patterns': list(jsrecon.api_patterns),
                'js_files': list(jsrecon.js_files),
                'secrets': list(jsrecon.secrets)
            }
    except Exception as e:
        print(f"{Fore.RED}[JS-RECON]{Style.RESET_ALL} Failed to analyze {url}: {e}")
        return None

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
                    
        # PHASE 4.25: JavaScript Reconnaissance
        if args.jsrecon:
            if args.url:  # Single URL mode
                print(f"\n{Fore.CYAN}[PHASE 4.25]{Style.RESET_ALL} JavaScript Reconnaissance")
                js_results = js_reconnaissance(args.url)
                if js_results:
                    target_results["js_recon"] = js_results
                    # Add any discovered endpoints to all_urls
                    for endpoint in js_results.get('endpoints', []):
                        if endpoint.startswith(('http://', 'https://')):
                            all_urls.add(endpoint)
            elif all_urls:  # Scan all discovered URLs
                print(f"\n{Fore.CYAN}[PHASE 4.25]{Style.RESET_ALL} JavaScript Reconnaissance")
                js_results = {}
                for url in all_urls:
                    url_js_results = js_reconnaissance(url)
                    if url_js_results:
                        js_results[url] = url_js_results
                        # Add any discovered endpoints to all_urls
                        for endpoint in url_js_results.get('endpoints', []):
                            if endpoint.startswith(('http://', 'https://')):
                                all_urls.add(endpoint)
                if js_results:
                    target_results["js_recon"] = js_results
        
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
        
        # PHASE 7: MODERN RECONNAISSANCE (2025)
        if args.full_scan or args.waf_detect or args.cloud_detect or args.api_scan or args.container_scan:
            print(f"\n{Fore.CYAN}[PHASE 7]{Style.RESET_ALL} Modern Infrastructure Detection")
            
            # WAF Detection & Fingerprinting
            if args.waf_detect or args.full_scan:
                print(f"\n{Fore.CYAN}[7.0]{Style.RESET_ALL} WAF/CDN Detection & Fingerprinting")
                base_url = f"https://{target}" if args.domain else (args.url if args.url else f"https://{target}")
                waf_info = detect_waf(target, base_url)
                
                if waf_info['detected']:
                    print(f"{Fore.YELLOW}[WAF-DETECTED]{Style.RESET_ALL} {len(waf_info['detected'])} WAF/Security solution(s) detected")
                    
                    for waf_name in waf_info['detected']:
                        confidence = waf_info['confidence'].get(waf_name, 0)
                        confidence_level = 'HIGH' if confidence >= 70 else ('MEDIUM' if confidence >= 50 else 'LOW')
                        confidence_color = Fore.RED if confidence >= 70 else (Fore.YELLOW if confidence >= 50 else Fore.CYAN)
                        
                        print(f"{Fore.GREEN}[WAF]{Style.RESET_ALL} {waf_name} - Confidence: {confidence_color}{confidence_level} ({confidence}%){Style.RESET_ALL}")
                        
                        if args.verbose and waf_name in waf_info['methods']:
                            print(f"  {Fore.CYAN}Detection Methods:{Style.RESET_ALL}")
                            for method in waf_info['methods'][waf_name][:3]:  # Show top 3 methods
                                print(f"    • {method}")
                    
                    # Show security headers
                    if waf_info['security_headers']:
                        print(f"\n{Fore.CYAN}[SECURITY-HEADERS]{Style.RESET_ALL} Found {len(waf_info['security_headers'])} security headers:")
                        for header, value in list(waf_info['security_headers'].items())[:5]:
                            display_value = value[:50] + '...' if len(value) > 50 else value
                            print(f"  • {header}: {display_value}")
                    
                    # AI-powered bypass recommendations
                    if waf_info['recommendations'] and args.verbose:
                        print(f"\n{Fore.YELLOW}[WAF-BYPASS-TIPS]{Style.RESET_ALL} AI-Powered Bypass Strategies:")
                        print(f"{Fore.CYAN}{'─'*80}{Style.RESET_ALL}")
                        for tip in waf_info['recommendations']:
                            if tip.startswith('🔍') or tip.startswith('⚙️') or tip.startswith('🎯') or tip.startswith('💉') or tip.startswith('🤖') or tip.startswith('📋') or tip.startswith('🔤') or tip.startswith('🎭') or tip.startswith('🧩') or tip.startswith('🌐'):
                                print(f"\n{Fore.YELLOW}{tip}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.WHITE}{tip}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}{'─'*80}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[WAF]{Style.RESET_ALL} No WAF detected (direct server access or unknown protection)")
                
                target_results["waf_detection"] = waf_info
            
            # Cloud Provider Detection
            if args.cloud_detect or args.full_scan:
                print(f"\n{Fore.CYAN}[7.1]{Style.RESET_ALL} Cloud Provider Detection")
                cloud_info = detect_cloud_provider(target)
                
                # Display Cloud Provider Info
                if cloud_info['provider'] != 'Unknown':
                    print(f"{Fore.GREEN}[CLOUD-PROVIDER]{Style.RESET_ALL} {cloud_info['provider']}")
                    
                    if cloud_info['region']:
                        print(f"{Fore.GREEN}[CLOUD-REGION]{Style.RESET_ALL} {cloud_info['region']}")
                    
                    if cloud_info['cdn']:
                        print(f"{Fore.GREEN}[CDN]{Style.RESET_ALL} {cloud_info['cdn']}")
                    
                    if cloud_info['waf']:
                        print(f"{Fore.YELLOW}[WAF]{Style.RESET_ALL} {cloud_info['waf']}")
                    
                    if cloud_info['services']:
                        print(f"{Fore.GREEN}[CLOUD-SERVICES]{Style.RESET_ALL} {', '.join(cloud_info['services'])}")
                    
                    if cloud_info['ips']:
                        print(f"{Fore.CYAN}[CLOUD-IPS]{Style.RESET_ALL} {', '.join(cloud_info['ips'][:3])}{'...' if len(cloud_info['ips']) > 3 else ''}")
                    
                    if args.verbose and cloud_info['evidence']:
                        print(f"{Fore.CYAN}[CLOUD-EVIDENCE]{Style.RESET_ALL}")
                        for ev in cloud_info['evidence']:
                            print(f"  • {ev}")
                else:
                    print(f"{Fore.YELLOW}[CLOUD]{Style.RESET_ALL} Provider not identified")
                
                # Cloud Storage Enumeration
                cloud_buckets = find_cloud_storage_buckets(target)
                
                # AI-Powered Cloud Vulnerability Scan (optional)
                cloud_vulns = []
                if (args.cloud_vuln or args.full_scan) and cloud_info['provider'] != 'Unknown':
                    print(f"\n{Fore.CYAN}[7.1.1]{Style.RESET_ALL} AI-Powered Cloud Vulnerability Scan")
                    cloud_vulns = ai_cloud_vulnerability_scan(target, cloud_info)
                
                target_results["cloud_detection"] = {
                    'provider_info': cloud_info,
                    'storage_buckets': cloud_buckets,
                    'vulnerabilities': cloud_vulns
                }
            
            # Subdomain Takeover Detection
            if (args.takeover_scan or args.full_scan) and all_subs:
                print(f"\n{Fore.CYAN}[7.2]{Style.RESET_ALL} Subdomain Takeover Detection")
                print(f"{Fore.YELLOW}[TAKEOVER]{Style.RESET_ALL} Scanning {len(all_subs)} subdomains for takeover vulnerabilities...")
                
                takeover_results = []
                vulnerable_count = 0
                critical_count = 0
                
                for subdomain in all_subs[:100]:  # Limit to first 100 subdomains to avoid slowness
                    takeover_info = detect_subdomain_takeover(subdomain)
                    
                    if takeover_info['service']:  # Found a service CNAME
                        if takeover_info['vulnerable']:
                            vulnerable_count += 1
                            if takeover_info['risk_level'] == 'CRITICAL':
                                critical_count += 1
                            
                            risk_color = Fore.RED if takeover_info['risk_level'] == 'CRITICAL' else (
                                Fore.YELLOW if takeover_info['risk_level'] in ['HIGH', 'POSSIBLE'] else Fore.CYAN
                            )
                            
                            print(f"\n{risk_color}[VULNERABLE]{Style.RESET_ALL} {subdomain}")
                            print(f"  {Fore.CYAN}Service:{Style.RESET_ALL} {takeover_info['service']}")
                            print(f"  {Fore.CYAN}CNAME:{Style.RESET_ALL} {takeover_info['cname']}")
                            print(f"  {Fore.CYAN}Risk Level:{Style.RESET_ALL} {risk_color}{takeover_info['risk_level']}{Style.RESET_ALL} ({takeover_info['confidence']}% confidence)")
                            
                            if args.verbose and takeover_info['indicators']:
                                print(f"  {Fore.CYAN}Indicators:{Style.RESET_ALL}")
                                for indicator in takeover_info['indicators']:
                                    print(f"    • {indicator}")
                            
                            # Show PoC steps if requested
                            if (args.takeover_poc or args.verbose) and takeover_info['poc_steps']:
                                print(f"  {Fore.YELLOW}[POC] Takeover Steps:{Style.RESET_ALL}")
                                for step in takeover_info['poc_steps']:
                                    print(f"    {step}")
                            
                            takeover_results.append({
                                'subdomain': subdomain,
                                'info': takeover_info
                            })
                
                # Summary
                if vulnerable_count > 0:
                    print(f"\n{Fore.RED}[TAKEOVER-SUMMARY]{Style.RESET_ALL} Found {vulnerable_count} potentially vulnerable subdomain(s)")
                    if critical_count > 0:
                        print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} {critical_count} CRITICAL risk takeover(s) detected!")
                else:
                    print(f"\n{Fore.GREEN}[TAKEOVER]{Style.RESET_ALL} No subdomain takeover vulnerabilities detected")
                
                target_results["takeover_detection"] = takeover_results
            
            # API Endpoint Discovery
            if args.api_scan or args.full_scan:
                print(f"\n{Fore.CYAN}[7.3]{Style.RESET_ALL} API Endpoint Discovery")
                # Scan primary domain/URL
                base_url = f"https://{target}" if args.domain else (args.url if args.url else f"https://{target}")
                api_results = discover_api_endpoints(target, base_url)
                
                # Enhanced GraphQL Introspection
                if api_results['graphql']:
                    for gql_endpoint in api_results['graphql']:
                        introspection_data = graphql_introspection(gql_endpoint['url'])
                        gql_endpoint['introspection'] = introspection_data
                
                target_results["api_discovery"] = api_results
            
            # Container/Kubernetes Detection
            if args.container_scan or args.full_scan:
                print(f"\n{Fore.CYAN}[7.4]{Style.RESET_ALL} Container Infrastructure Detection")
                container_results = detect_container_infrastructure(target)
                
                if container_results:
                    critical_count = len([c for c in container_results if c['severity'] == 'CRITICAL'])
                    if critical_count > 0:
                        print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} Found {critical_count} critical container exposures!")
                
                target_results["container_detection"] = container_results
        
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
    
    # Display Enhanced JavaScript Recon Summary
    total_js_files = 0
    total_frameworks = set()
    total_functions = 0
    total_events = 0
    total_ajax = 0
    total_websockets = 0
    total_endpoints = 0
    total_apis = 0
    total_secrets = 0
    
    for target, results in all_results.items():
        if 'js_recon' in results:
            js_data = results['js_recon']
            if isinstance(js_data, dict):
                if 'frameworks' in js_data:  # Single URL result with enhanced data
                    total_js_files += len(js_data.get('js_files', []))
                    total_frameworks.update(js_data.get('frameworks', {}).keys())
                    total_functions += len(js_data.get('functions', []))
                    total_events += len(js_data.get('event_handlers', []))
                    total_ajax += len(js_data.get('ajax_calls', []))
                    total_websockets += len(js_data.get('websockets', []))
                    total_endpoints += len(js_data.get('endpoints', []))
                    total_apis += len(js_data.get('api_patterns', []))
                    total_secrets += len(js_data.get('secrets', []))
                else:  # Multiple URL results
                    for url_data in js_data.values():
                        if isinstance(url_data, dict):
                            total_js_files += len(url_data.get('js_files', []))
                            total_frameworks.update(url_data.get('frameworks', {}).keys())
                            total_functions += len(url_data.get('functions', []))
                            total_events += len(url_data.get('event_handlers', []))
                            total_ajax += len(url_data.get('ajax_calls', []))
                            total_websockets += len(url_data.get('websockets', []))
                            total_endpoints += len(url_data.get('endpoints', []))
                            total_apis += len(url_data.get('api_patterns', []))
                            total_secrets += len(url_data.get('secrets', []))
    
    if total_js_files > 0:
        print(f"\n{Fore.CYAN}[JavaScript Reconnaissance Summary]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Files Analyzed:{Style.RESET_ALL} {total_js_files}")
        if total_frameworks:
            print(f"{Fore.CYAN}Frameworks Detected:{Style.RESET_ALL} {', '.join(total_frameworks)}")
        print(f"{Fore.CYAN}Functions Discovered:{Style.RESET_ALL} {total_functions}")
        print(f"{Fore.CYAN}Event Handlers:{Style.RESET_ALL} {total_events}")
        print(f"{Fore.CYAN}AJAX Calls:{Style.RESET_ALL} {total_ajax}")
        print(f"{Fore.CYAN}WebSocket Connections:{Style.RESET_ALL} {total_websockets}")
        print(f"{Fore.CYAN}API Endpoints:{Style.RESET_ALL} {total_apis}")
        print(f"{Fore.CYAN}Total Endpoints:{Style.RESET_ALL} {total_endpoints}")
        print(f"{Fore.RED}Sensitive Information Found:{Style.RESET_ALL} {total_secrets}")
    
    if ai_system.ollama_available:
        print(f"\n{Fore.MAGENTA}[AI]{Style.RESET_ALL} Ollama AI was used for intelligent subdomain selection and recursive discovery")
        print(f"{Fore.MAGENTA}[AI]{Style.RESET_ALL} AI Mode: {args.ai_mode.upper()} - Tested up to 75K subdomains with {args.levels} recursion levels")
    else:
        print(f"\n{Fore.CYAN}[AI]{Style.RESET_ALL} Heuristic AI was used - Tested up to 75K subdomains with {args.levels} recursion levels")

if __name__ == "__main__":
    run()
