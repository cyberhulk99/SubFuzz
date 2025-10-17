# SFUZZ — AI-Powered Security Fuzzing & Scanning Platform

## Quick Start

### 1. Install Dependencies

```bash
# Clone the repository
git clone https://github.com/sdicssh1999/SubFuzz.git
cd SubFuzz

# Create and activate virtual environment
python3 -m venv sfuzz-env
source sfuzz-env/bin/activate  # On Windows: sfuzz-env\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Install Ollama (Required for AI features)

The script includes an installation guide:
```bash
chmod +x install_ollama.sh
./install_ollama.sh
```

Or install manually:
- **macOS**: `brew install ollama`
- **Linux**: `curl -fsSL https://ollama.ai/install.sh | sh`
- **Other**: Visit [ollama.ai/download](https://ollama.ai/download)

After installation:
1. Start Ollama service: `ollama serve`
2. Download required model: `ollama pull llama2`
3. Verify installation: `ollama list`

**Author:** Suman Das
**Version:** 1.0.1
**License:** MIT

---

## Overview

SFUZZ is a next-generation security scanning platform that leverages advanced AI capabilities to revolutionize penetration testing and vulnerability assessment. Built with Python 3, it combines intelligent reconnaissance, smart fuzzing, and adaptive scanning techniques.

### Key Capabilities:

🤖 **Advanced AI Integration**
- Multiple AI operation modes: Fast, Smart, Aggressive, Deep
- Intelligent pattern recognition and learning
- AI-powered subdomain enumeration
- Smart wordlist generation
- Adaptive scanning strategies

🔍 **Comprehensive Reconnaissance**
- 15+ integrated passive sources
- Pattern-based subdomain discovery
- Intelligent DNS validation
- Advanced HTTP probing
- Recursive enumeration

🌐 **Enhanced Web Analysis**
- JavaScript reconnaissance
- Endpoint discovery
- Technology stack detection
- Framework identification
- Cloud service detection

⚡ **Performance & Reliability**
- Multi-threaded operations
- Smart error handling
- Adaptive rate limiting
- Progress monitoring
- Comprehensive reporting

The platform integrates seamlessly with Ollama for local AI model execution, ensuring both performance and data privacy. Whether you're conducting a quick assessment or an in-depth security audit, SFUZZ adapts its strategies based on the target and scanning context.

This repository contains:

* `sfuzz.py` — main Python script (the tool you provided)
* `install_ollama.sh` — Ollama auto-installer (bash)
* `wordlists/` — subdomain and directory wordlists
* `README.md` — this document
* `tools/` — optional external tools and integrations (see below)

---

## New: SubFuzz Integration

SFUZZ can integrate with the external SubFuzz repository to provide additional subdomain bruteforce and fuzzing functionality. Clone SubFuzz into the `tools/` directory to keep integrations organized.

To add SubFuzz:

```bash
# from the repo root
mkdir -p tools
git clone https://github.com/sdicssh1999/SubFuzz.git tools/SubFuzz
```

After cloning, review `tools/SubFuzz/README.md` for SubFuzz-specific usage. You can optionally add wrappers in `sfuzz.py` to call SubFuzz as a subprocess when `--use-subfuzz` (or similar) flag is implemented.

---

## Features

### AI-Powered Analysis
* Advanced AISubdomainAnalyzer for pattern-based enumeration
  - Intelligent pattern learning from discovered subdomains
  - Industry-specific pattern recognition
  - Adaptive subdomain generation
  - Multi-level recursive discovery

* Enhanced AIPenetrationSystem
  - Smart AI mode selection (fast, smart, aggressive, deep)
  - Real-time pattern analysis
  - Ollama integration for advanced AI capabilities
  - Intelligent wordlist generation

### Reconnaissance
* Comprehensive Passive Recon from 15+ sources:
  - Certificate Transparency logs (crt.sh)
  - Wayback Machine analysis
  - DNS records analysis
  - Multiple API integrations
  - Common subdomain patterns

* Advanced Active Enumeration
  - AI-driven wordlist selection
  - Pattern-based recursive discovery
  - Intelligent DNS validation
  - HTTP/HTTPS probing with robust error handling

### Web Analysis
* JavaScript Reconnaissance
  - Automated JS file discovery
  - API endpoint extraction
  - Secret detection
  - Import analysis
  - WebSocket endpoint detection

* Enhanced Technology Stack Detection
  - Framework identification
  - Cloud service detection
  - Security tool recognition
  - Infrastructure analysis
  - CMS identification

### Security Features
* Multi-threaded scanning capabilities
* Intelligent error handling
* Rate limiting and timeout controls
* Stealth mode for careful scanning
* Comprehensive output formats

---

## Prerequisites

* Python 3.8+
* `pip` for Python packages
* Optional (recommended): `nuclei` installed and in `$PATH`
* Optional: `ollama` and one or more models (for AI features)

### Wordlists
The tool requires wordlists for effective scanning. Due to size constraints, large wordlists are not included in the repository. You can:

1. Download the Assetnote 2M subdomains wordlist (recommended):
```bash
mkdir -p wordlists/subdomains
wget -O wordlists/subdomains/2m-subdomains.txt https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt
# If wget is not available, use curl:
# curl -o wordlists/subdomains/2m-subdomains.txt https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt
```

This wordlist contains over 2 million unique subdomains gathered from various sources including:
- DNS datasets
- CommonCrawl data
- Certificate Transparency logs
- Web crawling results
- Public datasets

2. Or use your own custom wordlists by placing them in:
   - `wordlists/subdomains/` - for subdomain wordlists
   - `wordlists/dirs/` - for directory wordlists

Python dependencies (install with pip):

```bash
pip install -r requirements.txt
# or individually:
pip install requests colorama beautifulsoup4 dnspython
```

Create a `requirements.txt` with at least:

```
requests
colorama
beautifulsoup4
dnspython
```

---

## Installation

1. Clone the repo:

```bash
git clone <repo-url>
cd sfuzz
```

2. Install Python dependencies (see Prerequisites).

3. (Optional) Install `nuclei` by following the official docs (`https://github.com/projectdiscovery/nuclei`).

4. (Optional) If you want AI features, install Ollama:

* Manual way: follow the instructions at `https://ollama.ai` for your OS.
* Automated: run the provided installer script `install_ollama.sh` (see **Ollama Installer** section below).

5. (Optional) Add integrations like SubFuzz:

```bash
# clone SubFuzz into the tools folder
mkdir -p tools
git clone https://github.com/sdicssh1999/SubFuzz.git tools/SubFuzz
```

---

## install_ollama.sh (Ollama Auto-Installer)

A helper script, `install_ollama.sh`, is included to simplify Ollama setup (it will not bypass the official install steps where required). Make the script executable and run it as root or with sudo:

```bash
chmod +x install_ollama.sh
sudo ./install_ollama.sh
```

**What the installer does (high level):**

* Checks whether `ollama` binary is present
* Attempts to start the Ollama service (via `brew services` on macOS if available, or `ollama serve` directly)
* Attempts to pull a list of models (defaults try `llama2` and `codellama`) using `ollama pull`
* Verifies the service is accessible at `http://localhost:11434`

> Note: Ollama distribution packaging and installation requires platform-specific steps (root permissions). The script guides you and provides manual steps if automatic install is not possible.

---

## Usage

Basic usage patterns (run `python3 sfuzz.py -h` for full options):

```bash
# Recon only (passive + active) for example.com
python3 sfuzz.py -d example.com --recon

# Quick scan (brute-force + quick portscan)
python3 sfuzz.py -d example.com --quick

# Full penetration-style scan with AI enabled (deep mode will be auto-selected by --full-scan)
python3 sfuzz.py -d example.com --full-scan

# Use a custom wordlist for active bruteforce
python3 sfuzz.py -d example.com --wordlist wordlists/subdomains/custom.txt --active

# Save discovered subdomains to a file
python3 sfuzz.py -d example.com --recon -o discovered.txt
```

### Common flags

* `-d/--domain` — Target domain
* `-u/--url` — Single URL
* `-i/--input` — File with a list of targets
* `--workers` — Number of threads (default 30)
* `--timeout` — Request timeout (seconds)
* `--ai-mode` — One of `off`, `fast`, `smart`, `aggressive`, `deep`
* `--nuclei-scan` — Enable Nuclei scanning (requires `nuclei` binary)

---

## AI / Ollama Integration

* SFUZZ will attempt to talk to a local Ollama service at `http://localhost:11434`.
* If Ollama is reachable and has models available, SFUZZ enables stronger AI-powered features: smarter wordlist selection and analysis.
* If Ollama is not installed or not running, SFUZZ will fall back to the built-in heuristic AI and still run.

**Enabling AI features:**

* Install Ollama and pull models (see `install_ollama.sh` or manual install).
* Ensure the Ollama service is running (`ollama serve`) and reachable at port `11434`.
* Run SFUZZ with `--ai-mode smart` (default), or choose `fast`, `aggressive`, or `deep`.

**If you do NOT want SFUZZ to try to auto-download or use AI models, run with:**

```bash
python3 sfuzz.py -d example.com --ai-mode off --no-ai-download
```

---

## Integration Tips

* To call SubFuzz from SFUZZ, add a small wrapper function in `sfuzz.py` that runs SubFuzz with subprocess and captures output. Example pseudocode in Python:

```python
subfuzz_cmd = ["python3", "tools/SubFuzz/subfuzz.py", "-d", domain, "--wordlist", "wordlists/subdomains/custom.txt"]
proc = subprocess.run(subfuzz_cmd, capture_output=True, text=True, timeout=300)
# parse proc.stdout and add discovered subdomains to discovered_subdomains set
```

* Keep external tools in `tools/` and refer to them from the main script. Add CLI flags to enable/disable each integration.

---

## Notes & Best Practices

* Run this tool only against systems you own or have explicit written permission to test.
* Use `--stealth` to reduce request rate and lower detection footprint.
* Large scans may generate high network/target load — consider throttling `--workers` and increasing `--timeout` for unstable targets.
* The tool attempts to be defensive: it treats any HTTP status < 500 as an indicator of a live host.

---

## Troubleshooting

* **Ollama not starting:** Inspect `/tmp/ollama.log` (the installer writes logs there when starting `ollama serve`), and run `ollama serve` manually to view live output.
* **crt.sh or Wayback API failures:** Often transient — try again or increase `--timeout`.
* **Nuclei CLI issues:** Ensure `nuclei` is in your `$PATH` and you have an up-to-date templates repository.

---

## Contributing

Contributions are welcome. Please open issues/PRs for new integrations, bug fixes, or improvements. Keep PRs small and focused.

Suggested areas:

* Add support for ProjectDiscovery tools (subfinder, httpx, gau) as optional subprocess integrations
* Replace basic socket-based port scanning with `nmap`-driven scans for accuracy
* Improve result export formats (CSV/HTML/JSON)

---

## License

MIT © Suman Das

---

## Changelog (high-level)

* v1.0.1 — Feature Enhancement Release (October 17, 2025):
  - Added version fingerprinting in technology detection
  - Enhanced vulnerability scanning capabilities
  - Improved XSS detection with stored XSS support
  - Added time-based SQL injection detection
  - Enhanced crawling with form detection
  - Improved JavaScript parsing and analysis
  - Added comprehensive error handling system
  - Added smart rate limiting with domain intelligence
  - Implemented state management for scan resumption
  - Enhanced security headers analysis
  - Improved AI-powered subdomain discovery

* v1.0.0 — Initial Release with Advanced Features:
  - Implemented AISubdomainAnalyzer with pattern learning
  - Enhanced AIPenetrationSystem with Ollama integration
  - Added comprehensive JavaScript reconnaissance
  - Advanced technology stack detection
  - Intelligent directory scanning with AI path prediction
  - Multi-source passive reconnaissance
  - Enhanced active enumeration capabilities
