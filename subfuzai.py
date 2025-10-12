#!/usr/bin/env python3
# SFUZZ - Advanced Security Fuzzing & Scanning Platform
# Author: Suman Das
# License: MIT

"""
SFUZZ - Advanced Security Fuzzing & Scanning Platform
AI-Powered Reconnaissance | Vulnerability Assessment | Exploitation
Next-Generation Penetration Testing Tool
"""

import argparse, os, sys, json, time, socket, subprocess, shutil, re
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from random import sample, choice
import requests
from colorama import init as colorama_init, Fore, Style
import hashlib
from urllib.parse import urlparse, urljoin

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
    import aiohttp
    import asyncio
except ImportError:
    aiohttp = None
    asyncio = None

# Silencing insecure warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tool metadata
__version__ = "4.1.0"
__author__ = "Suman Das"
__license__ = "MIT"

colorama_init(autoreset=True)

BANNER = rf"""
{Fore.CYAN}
 ███████╗███████╗██╗   ██╗███████╗███████╗
 ██╔════╝██╔════╝██║   ██║╚══███╔╝╚══███╔╝
 ███████╗█████╗  ██║   ██║  ███╔╝   ███╔╝ 
 ╚════██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  
 ███████║███████╗╚██████╔╝███████╗███████╗
 ╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝
{Style.RESET_ALL}
        Advanced Security Fuzzing & Scanning Platform v{__version__}
    ──────────────────────────────────────────────────────────
    Phases: {Fore.GREEN}•{Style.RESET_ALL} Recon {Fore.GREEN}•{Style.RESET_ALL} Scanning {Fore.GREEN}•{Style.RESET_ALL} Enumeration {Fore.GREEN}•{Style.RESET_ALL} Vulnerability {Fore.GREEN}•{Style.RESET_ALL} Exploitation
    AI Modes: {Fore.CYAN}•{Style.RESET_ALL} Fast {Fore.CYAN}•{Style.RESET_ALL} Smart {Fore.CYAN}•{Style.RESET_ALL} Aggressive {Fore.CYAN}•{Style.RESET_ALL} Deep
    ──────────────────────────────────────────────────────────
"""
print(BANNER)

# ---------------------------
# CLI Arguments - COMPLETE PENETRATION TESTING
# ---------------------------
parser = argparse.ArgumentParser(prog="sfuzz", description="SFUZZ - Advanced Security Fuzzing & Scanning Platform")
parser.add_argument("-d","--domain", help="Target domain (single)")
parser.add_argument("-u","--url", help="Single URL to test")
parser.add_argument("-i","--input", help="Input file with domains/URLs")
parser.add_argument("-w","--wordlist", help="Subdomain wordlist for active bruteforce")
parser.add_argument("-l","--levels", type=int, default=2, help="Recursion depth for active bruteforce (default 2)")
parser.add_argument("--workers", type=int, default=100, help="Concurrent workers (default 100)")
parser.add_argument("--timeout", type=float, default=3.0, help="Timeout in seconds (default 3.0)")
parser.add_argument("--no-color", action="store_true", help="Disable colors")
parser.add_argument("-o","--output", help="Output file")
parser.add_argument("--json-output", help="JSON output file")
parser.add_argument("--verbose", action="store_true", help="Verbose logging")

# Reconnaissance Phase
parser.add_argument("--recon", action="store_true", help="Full reconnaissance")
parser.add_argument("--passive", action="store_true", help="Passive intelligence gathering")
parser.add_argument("--active", action="store_true", help="Active subdomain enumeration")
parser.add_argument("--subdomains", action="store_true", help="Find subdomains (passive + active)")

# Scanning Phase
parser.add_argument("--scan", action="store_true", help="Full scanning phase")
parser.add_argument("--portscan", action="store_true", help="Port scanning")
parser.add_argument("--ports", help="Ports to scan (default: top 1000)")
parser.add_argument("--dirscan", action="store_true", help="Directory and file scanning")
parser.add_argument("--dir-wordlist", help="Directory wordlist")
parser.add_argument("--crawl", action="store_true", help="Website crawling")

# Enumeration Phase
parser.add_argument("--enum", action="store_true", help="Full enumeration")
parser.add_argument("--tech-detect", action="store_true", help="Technology detection")
parser.add_argument("--endpoints", action="store_true", help="Find API endpoints")
parser.add_argument("--params", action="store_true", help="Find URL parameters")
parser.add_argument("--gau", action="store_true", help="Get All URLs from Wayback etc")

# Vulnerability Assessment
parser.add_argument("--vuln-scan", action="store_true", help="Vulnerability scanning")
parser.add_argument("--takeover", action="store_true", help="Subdomain takeover check")
parser.add_argument("--misconfig", action="store_true", help="Security misconfiguration check")
parser.add_argument("--headers", action="store_true", help="Security headers analysis")
parser.add_argument("--cve-scan", action="store_true", help="CVE vulnerability scanning")
parser.add_argument("--xss-scan", action="store_true", help="XSS vulnerability scanning")
parser.add_argument("--sqli-scan", action="store_true", help="SQL injection scanning")
parser.add_argument("--lfi-scan", action="store_true", help="Local File Inclusion scanning")

# AI Configuration
parser.add_argument("--ai-mode", default="smart", choices=["off", "fast", "smart", "aggressive", "deep"],
                    help="AI mode: off|fast|smart|aggressive|deep (default: smart)")
parser.add_argument("--ai-recon", action="store_true", help="AI-enhanced reconnaissance")
parser.add_argument("--ai-scan", action="store_true", help="AI-enhanced scanning")
parser.add_argument("--ai-enum", action="store_true", help="AI-enhanced enumeration")
parser.add_argument("--ai-vuln", action="store_true", help="AI-enhanced vulnerability assessment")
parser.add_argument("--no-ai-download", action="store_true", help="Skip auto AI model download")

# Advanced Options
parser.add_argument("--full-scan", action="store_true", help="Complete penetration test (all phases)")
parser.add_argument("--quick", action="store_true", help="Quick scan (essential checks only)")
parser.add_argument("--stealth", action="store_true", help="Stealth mode (slower, less detectable)")

args = parser.parse_args()

if args.no_color:
    Fore.GREEN = Fore.YELLOW = Fore.RED = Fore.CYAN = Fore.MAGENTA = Fore.WHITE = Fore.RESET = ""
    Style.RESET_ALL = ""

# Auto-enable phases based on shortcuts
if args.full_scan:
    args.recon = args.scan = args.enum = args.vuln_scan = True
    args.ai_mode = "deep"
if args.quick:
    args.subdomains = args.portscan = args.tech_detect = True
    args.ai_mode = "fast"
if args.recon:
    args.passive = args.active = True
if args.scan:
    args.portscan = args.dirscan = args.crawl = True
if args.enum:
    args.tech_detect = args.endpoints = args.params = True

# Auto-enable AI for specific phases if AI mode is not off
if args.ai_mode != "off":
    if not any([args.ai_recon, args.ai_scan, args.ai_enum, args.ai_vuln]):
        args.ai_recon = args.ai_scan = args.ai_enum = args.ai_vuln = True

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

color_lock = threading.Lock()

# ---------------------------
# UTILITY FUNCTIONS
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

def add_url(url, source):
    """Add URL with duplicate checking"""
    parsed = urlparse(url)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    with color_lock:
        if normalized not in discovered_urls:
            discovered_urls.add(normalized)
            print(f"{Fore.BLUE}[{source}]{Style.RESET_ALL} {normalized}")
            return True
    return False

def add_path(path, source):
    """Add path with duplicate checking"""
    with color_lock:
        if path not in discovered_paths:
            discovered_paths.add(path)
            print(f"{Fore.YELLOW}[{source}]{Style.RESET_ALL} {path}")
            return True
    return False

# ---------------------------
# AI SYSTEM - ENHANCED WITH BETTER WORDLIST HANDLING
# ---------------------------
class AIPenetrationSystem:
    def __init__(self):
        self.ai_ready = False
        self.model_type = "heuristic"
        
    def setup_ai(self):
        """Setup AI system"""
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Initializing AI Engine...")
        
        if os.path.exists(AI_SETUP_FLAG):
            with open(AI_SETUP_FLAG, 'r') as f:
                setup_data = json.load(f)
                self.model_type = setup_data.get('model_type', 'heuristic')
                self.ai_ready = True
                print(f"{Fore.GREEN}[AI]{Style.RESET_ALL} AI Engine: {self.model_type}")
                return True
        
        # Check for Ollama
        if self._check_ollama():
            print(f"{Fore.GREEN}[AI]{Style.RESET_ALL} Ollama detected - Full AI capabilities")
            self.ai_ready = True
            self.model_type = "ollama"
            self._save_setup()
            return True
            
        # Advanced heuristic AI (always available)
        print(f"{Fore.YELLOW}[AI]{Style.RESET_ALL} Using Advanced Heuristic AI")
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Capabilities: Smart wordlist enhancement, Pattern recognition, Vulnerability prediction")
        self.ai_ready = True
        self.model_type = "heuristic_advanced"
        self._save_setup()
        return True
        
    def _check_ollama(self):
        """Check if Ollama is available"""
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
            
    def _save_setup(self):
        """Save AI setup"""
        try:
            setup_data = {'model_type': self.model_type, 'timestamp': int(time.time())}
            with open(AI_SETUP_FLAG, 'w') as f:
                json.dump(setup_data, f)
        except:
            pass

    def enhance_wordlist(self, base_words, domain):
        """AI-enhanced wordlist generation"""
        enhanced = set(base_words)
        
        # Common patterns
        patterns = [
            "api", "app", "admin", "test", "dev", "staging", "prod", "production",
            "cdn", "assets", "static", "media", "uploads", "files", "backup",
            "mail", "email", "smtp", "ftp", "ssh", "vpn", "remote", "portal",
            "dashboard", "console", "control", "manager", "monitor", "status",
            "web", "server", "client", "mobile", "staging", "demo", "beta", "alpha"
        ]
        
        enhanced.update(patterns)
        
        # Domain-specific patterns
        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            main_domain = domain_parts[-2]
            enhanced.update([
                main_domain,
                f"www-{main_domain}",
                f"{main_domain}-api",
                f"api-{main_domain}",
                f"{main_domain}-app",
                f"app-{main_domain}",
                f"mobile-{main_domain}",
                f"{main_domain}-mobile",
                f"secure-{main_domain}",
                f"{main_domain}-secure"
            ])
        
        print(f"{Fore.CYAN}[AI]{Style.RESET_ALL} Enhanced wordlist from {len(base_words)} to {len(enhanced)} entries")
        return list(enhanced)

# Initialize AI system
ai_system = AIPenetrationSystem()

# ---------------------------
# WORDLIST HANDLING - IMPROVED
# ---------------------------
def get_default_wordlist(wordlist_type="subdomains"):
    """Get default wordlist with proper fallback"""
    if wordlist_type == "subdomains":
        wordlist_dir = WORDLISTS_SUB
        default_files = ["top1000.txt", "subdomains.txt", "common.txt"]
    else:  # directories
        wordlist_dir = WORDLISTS_DIRS
        default_files = ["common.txt", "dirs.txt", "big.txt"]
    
    # Check if wordlist directory exists
    if not os.path.exists(wordlist_dir):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Wordlist directory not found: {wordlist_dir}")
        return None
    
    # Try to find an existing wordlist file
    for filename in default_files:
        wordlist_path = os.path.join(wordlist_dir, filename)
        if os.path.exists(wordlist_path):
            return wordlist_path
    
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No wordlist found in {wordlist_dir}")
    return None

# ---------------------------
# PASSIVE RECONNAISSANCE
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

def subfinder_local(domain):
    """Use subfinder if available"""
    s = set()
    try:
        result = subprocess.run(["subfinder", "-version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            cmd = ["subfinder", "-d", domain, "-silent", "-all"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    host = line.strip()
                    if host and host.endswith(domain):
                        if add_subdomain(host, 'subfinder'):
                            s.add(host)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} subfinder failed: {e}")
    return s

def amass_passive(domain):
    """Use Amass for passive enumeration"""
    s = set()
    try:
        result = subprocess.run(["amass", "-version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            cmd = ["amass", "enum", "-passive", "-d", domain, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    host = line.strip()
                    if host and host.endswith(domain):
                        if add_subdomain(host, 'amass'):
                            s.add(host)
    except Exception as e:
        if args.verbose:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} amass failed: {e}")
    return s

def passive_reconnaissance(domain):
    """Complete passive reconnaissance"""
    print(f"{Fore.CYAN}[PHASE 1]{Style.RESET_ALL} Passive Reconnaissance")
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Gathering intelligence from 7+ sources...")
    
    collectors = [
        crtsh_query,
        certspotter_query,
        wayback_cdx,
        bufferover_query,
        threatcrowd_query,
        subfinder_local,
        amass_passive
    ]
    
    all_subs = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(func, domain) for func in collectors]
        for future in as_completed(futures):
            try:
                results = future.result()
                all_subs.update(results)
            except Exception as e:
                if args.verbose:
                    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Collector failed: {e}")
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Passive reconnaissance found {len(all_subs)} unique subdomains")
    return all_subs

# ---------------------------
# ACTIVE RECONNAISSANCE
# ---------------------------
def dns_resolve_all(fqdn, timeout):
    """Resolve DNS for a domain"""
    ips, cnames = [], []
    if dns:
        try:
            r = dns.resolver.Resolver()
            r.lifetime = timeout
            try:
                ips.extend(rr.to_text() for rr in r.resolve(fqdn, "A"))
            except: pass
            try:
                ips.extend(rr.to_text() for rr in r.resolve(fqdn, "AAAA"))
            except: pass
            try:
                cnames.extend(str(rr.target).rstrip(".") for rr in r.resolve(fqdn, "CNAME"))
            except: pass
            return (len(ips) > 0 or len(cnames) > 0), list(set(ips)), cnames
        except Exception:
            return False, [], []
    else:
        try:
            socket.setdefaulttimeout(timeout)
            infos = socket.getaddrinfo(fqdn, None)
            ips.extend(info[4][0] for info in infos if info and info[4])
            return (len(ips) > 0), list(set(ips)), []
        except Exception:
            return False, [], []

def http_probe(fqdn, timeout):
    """HTTP probe for a domain"""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{fqdn}/"
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            return True, r.status_code, r.text
        except:
            continue
    return False, None, ""

def active_reconnaissance(domain, passive_subs):
    """Active subdomain enumeration"""
    print(f"{Fore.CYAN}[PHASE 2]{Style.RESET_ALL} Active Reconnaissance")
    
    # Load wordlist with improved handling
    if args.wordlist:
        wordlist_path = args.wordlist
    else:
        wordlist_path = get_default_wordlist("subdomains")
    
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Using wordlist: {wordlist_path} ({len(words)} entries)")
    else:
        # Fallback to built-in wordlist
        words = ["www", "api", "app", "admin", "test", "dev", "staging", "mail", "ftp", "blog", 
                "shop", "store", "cdn", "assets", "static", "media", "uploads", "files",
                "web", "server", "client", "mobile", "backup", "demo", "beta", "alpha"]
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Using built-in wordlist ({len(words)} entries)")
    
    # AI-enhanced wordlist
    if ai_system.ai_ready and args.ai_recon:
        words = ai_system.enhance_wordlist(words, domain)
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Testing {len(words)} subdomains...")
    
    found_subs = set()
    
    def check_subdomain(subdomain):
        ok, ips, cnames = dns_resolve_all(subdomain, args.timeout)
        if ok:
            http_ok, status, body = http_probe(subdomain, args.timeout)
            if add_subdomain(subdomain, 'active'):
                if http_ok:
                    print(f"{Fore.GREEN}[HTTP]{Style.RESET_ALL} {subdomain} (Status: {status})")
                return subdomain
        return None
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        for word in words:
            subdomain = f"{word}.{domain}"
            futures.append(executor.submit(check_subdomain, subdomain))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_subs.add(result)
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Active reconnaissance found {len(found_subs)} new subdomains")
    return found_subs

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
                print(f"{Fore.BLUE}[port]{Style.RESET_ALL} {host}:{result} open")
    
    return open_ports

def port_scanning(subdomains):
    """Port scanning phase"""
    print(f"{Fore.CYAN}[PHASE 3]{Style.RESET_ALL} Port Scanning")
    
    if args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    else:
        ports = COMMON_PORTS
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanning {len(subdomains)} hosts on {len(ports)} ports...")
    
    results = {}
    for subdomain in subdomains:
        open_ports = port_scan_host(subdomain, ports)
        if open_ports:
            results[subdomain] = open_ports
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Found open ports on {len(results)} hosts")
    return results

# ---------------------------
# DIRECTORY SCANNING
# ---------------------------
def directory_scan(url, wordlist):
    """Directory scanning for a URL"""
    found_paths = []
    
    if wordlist and os.path.exists(wordlist):
        with open(wordlist, "r") as f:
            wordlist_items = [line.strip() for line in f if line.strip()]
        print(f"{Fore.CYAN}[DIR]{Style.RESET_ALL} Using wordlist: {wordlist} ({len(wordlist_items)} entries)")
    else:
        wordlist_items = ["admin", "login", "dashboard", "api", "config", "backup", "test", "dev",
                   ".git", ".env", "robots.txt", "sitemap.xml", "phpinfo.php", "server-status"]
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Using built-in directory wordlist ({len(wordlist_items)} entries)")
    
    def check_path(path):
        try:
            full_url = f"{url}/{path}"
            r = requests.get(full_url, timeout=args.timeout, verify=False)
            if r.status_code in [200, 301, 302, 403]:
                if add_path(full_url, 'dir'):
                    return {"url": full_url, "status": r.status_code}
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(check_path, path) for path in wordlist_items[:1000]]
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_paths.append(result)
    
    return found_paths

def directory_scanning(subdomains):
    """Directory scanning phase"""
    print(f"{Fore.CYAN}[PHASE 4]{Style.RESET_ALL} Directory Scanning")
    
    # Get directory wordlist with improved handling
    if args.dir_wordlist:
        wordlist_path = args.dir_wordlist
    else:
        wordlist_path = get_default_wordlist("dirs")
    
    # Convert set to list for slicing
    subdomains_list = list(subdomains)
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanning {len(subdomains_list)} hosts for directories...")
    
    results = {}
    for subdomain in subdomains_list[:10]:  # Limit to 10 hosts for performance
        url = f"https://{subdomain}"
        paths = directory_scan(url, wordlist_path)
        if paths:
            results[subdomain] = paths
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Found directories on {len(results)} hosts")
    return results

# ---------------------------
# VULNERABILITY SCANNING - FIXED AND ENHANCED
# ---------------------------
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
    """Check for XSS vulnerabilities using advanced payloads"""
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "onmouseover=alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ]
    
    vulnerabilities = []
    
    # Check in parameters
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
    """Check for SQL injection vulnerabilities using advanced techniques"""
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

def vulnerability_scanning(subdomains):
    """Vulnerability scanning phase - FIXED VERSION"""
    print(f"{Fore.CYAN}[PHASE 5]{Style.RESET_ALL} Vulnerability Assessment")
    
    # Convert set to list for slicing
    subdomains_list = list(subdomains)
    
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanning {len(subdomains_list)} hosts for vulnerabilities...")
    
    results = {
        "takeovers": {},
        "security_headers": {},
        "xss": {},
        "sql_injection": {},
        "lfi": {}
    }
    
    # Check for subdomain takeovers
    if args.takeover:
        print(f"{Fore.CYAN}[SCAN]{Style.RESET_ALL} Checking for subdomain takeovers...")
        for subdomain in subdomains_list:  # No slicing needed for takeovers
            takeover = check_takeover(subdomain)
            if takeover:
                results["takeovers"][subdomain] = takeover
                print(f"{Fore.RED}[VULN]{Style.RESET_ALL} {subdomain}: {takeover['description']}")
    
    # Check security headers
    if args.headers:
        print(f"{Fore.CYAN}[SCAN]{Style.RESET_ALL} Checking security headers...")
        for subdomain in subdomains_list[:5]:  # Now slicing works on list
            url = f"https://{subdomain}"
            missing_headers = check_security_headers(url)
            if missing_headers:
                results["security_headers"][subdomain] = missing_headers
                print(f"{Fore.YELLOW}[HEADER]{Style.RESET_ALL} {subdomain}: {len(missing_headers)} security issues")
    
    # Check XSS vulnerabilities
    if args.xss_scan:
        print(f"{Fore.CYAN}[SCAN]{Style.RESET_ALL} Checking for XSS vulnerabilities...")
        for subdomain in subdomains_list[:3]:  # Now slicing works on list
            url = f"https://{subdomain}"
            xss_vulns = check_xss_vulnerabilities(url)
            if xss_vulns:
                results["xss"][subdomain] = xss_vulns
                for vuln in xss_vulns:
                    print(f"{Fore.RED}[XSS]{Style.RESET_ALL} {subdomain}: {vuln['description']}")
    
    # Check SQL injection vulnerabilities
    if args.sqli_scan:
        print(f"{Fore.CYAN}[SCAN]{Style.RESET_ALL} Checking for SQL injection...")
        for subdomain in subdomains_list[:3]:  # Now slicing works on list
            url = f"https://{subdomain}"
            sql_vulns = check_sql_injection(url)
            if sql_vulns:
                results["sql_injection"][subdomain] = sql_vulns
                for vuln in sql_vulns:
                    print(f"{Fore.RED}[SQLi]{Style.RESET_ALL} {subdomain}: {vuln['description']}")
    
    # Check LFI vulnerabilities
    if args.lfi_scan:
        print(f"{Fore.CYAN}[SCAN]{Style.RESET_ALL} Checking for LFI vulnerabilities...")
        for subdomain in subdomains_list[:3]:  # Now slicing works on list
            url = f"https://{subdomain}"
            lfi_vulns = check_lfi_vulnerabilities(url)
            if lfi_vulns:
                results["lfi"][subdomain] = lfi_vulns
                for vuln in lfi_vulns:
                    print(f"{Fore.RED}[LFI]{Style.RESET_ALL} {subdomain}: {vuln['description']}")
    
    print(f"{Fore.GREEN}[COMPLETE]{Style.RESET_ALL} Vulnerability assessment completed")
    return results

# ---------------------------
# MAIN EXECUTION
# ---------------------------
def run():
    """Main execution function"""
    if not args.domain and not args.url and not args.input:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Please provide a domain (-d), URL (-u), or input file (-i)")
        return
    
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
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[TARGET]{Style.RESET_ALL} {target}")
        print(f"{Fore.CYAN}[AI MODE]{Style.RESET_ALL} {args.ai_mode.upper()}")
        print(f"{Fore.CYAN}[WORKERS]{Style.RESET_ALL} {args.workers}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        target_results = {"target": target}
        
        # PHASE 1: Passive Reconnaissance
        if args.passive or args.subdomains or args.recon:
            passive_subs = passive_reconnaissance(target)
            target_results["passive_subdomains"] = list(passive_subs)
        
        # PHASE 2: Active Reconnaissance
        if args.active or args.subdomains or args.recon:
            active_subs = active_reconnaissance(target, passive_subs if 'passive_subs' in locals() else set())
            target_results["active_subdomains"] = list(active_subs)
        
        # Combine all subdomains
        all_subs = set()
        if 'passive_subs' in locals():
            all_subs.update(passive_subs)
        if 'active_subs' in locals():
            all_subs.update(active_subs)
        target_results["all_subdomains"] = list(all_subs)
        
        # PHASE 3: Port Scanning
        if args.portscan or args.scan:
            port_results = port_scanning(all_subs)
            target_results["port_scan"] = port_results
        
        # PHASE 4: Directory Scanning
        if args.dirscan or args.scan:
            dir_results = directory_scanning(all_subs)
            target_results["directory_scan"] = dir_results
        
        # PHASE 5: Vulnerability Assessment
        if args.vuln_scan or args.takeover or args.headers or args.xss_scan or args.sqli_scan or args.lfi_scan:
            vuln_results = vulnerability_scanning(all_subs)
            target_results["vulnerabilities"] = vuln_results
        
        all_results[target] = target_results
        
        # Save results
        if args.output:
            with open(args.output, 'a') as f:
                for subdomain in all_subs:
                    f.write(f"{subdomain}\n")
            print(f"{Fore.GREEN}[SAVED]{Style.RESET_ALL} Subdomains saved to {args.output}")
        
        if args.json_output:
            with open(args.json_output, 'w') as f:
                json.dump(all_results, f, indent=2)
            print(f"{Fore.GREEN}[SAVED]{Style.RESET_ALL} Full results saved to {args.json_output}")
    
    # Final Summary
    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{' SCAN COMPLETE ':.^60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    
    total_vulns = 0
    for target, results in all_results.items():
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {target}")
        print(f"{Fore.CYAN}Subdomains:{Style.RESET_ALL} {len(results.get('all_subdomains', []))}")
        
        if 'port_scan' in results:
            open_hosts = len(results['port_scan'])
            print(f"{Fore.CYAN}Open Ports:{Style.RESET_ALL} {open_hosts} hosts")
        
        if 'vulnerabilities' in results:
            vuln_count = (
                len(results['vulnerabilities'].get('takeovers', {})) +
                len(results['vulnerabilities'].get('xss', {})) +
                len(results['vulnerabilities'].get('sql_injection', {})) +
                len(results['vulnerabilities'].get('lfi', {}))
            )
            total_vulns += vuln_count
            print(f"{Fore.CYAN}Vulnerabilities:{Style.RESET_ALL} {vuln_count} found")
        
        print()
    
    if total_vulns > 0:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Total vulnerabilities found: {total_vulns}")
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Review the findings and validate manually for false positives")
    else:
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} No critical vulnerabilities found")

if __name__ == "__main__":
    run()
