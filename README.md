# SFUZZ — AI-Powered Security Fuzzing & Scanning Platform

**Author:** @cyberhulk99 (From non-tech to security tooling)
**Version:** 1.0.1
**License:** MIT

---

## Overview

SFUZZ is a next-generation security scanning platform that leverages advanced AI capabilities to revolutionize penetration testing and vulnerability assessment. Built with Python 3, it combines intelligent reconnaissance, smart fuzzing, and adaptive scanning techniques.

### Key Capabilities:

🤖 **Advanced AI Integration**
- 4 Specialized AI Modes: Fast/Smart/Aggressive/Deep
- Intelligent pattern recognition and learning
- Self-learning subdomain patterns
- Smart wordlist generation
- Adaptive scanning strategies

🔍 **Comprehensive Reconnaissance**
- 15+ integrated passive sources (crt.sh, certspotter, wayback, etc.)
- AI-enhanced pattern-based discovery
- Intelligent DNS validation
- Advanced HTTP probing
- Recursive enumeration

🌐 **Next-Gen JavaScript Analysis**
- Smart endpoint and API discovery
- Hidden endpoint detection
- Async processing for efficient operations
- Pattern-based API identification
- Real-time dependency analysis
- WebSocket endpoint detection

⚡ **Intelligent Scanning System**
- Smart HTTP/HTTPS probing
- Context-aware port scanning
- AI-driven directory enumeration
- Dynamic crawling with pattern recognition
- Multi-threaded operations
- Progress monitoring

The platform integrates seamlessly with Ollama for local AI model execution, ensuring both performance and data privacy. Whether you're conducting a quick assessment or an in-depth security audit, SFUZZ adapts its strategies based on the target and scanning context.

This repository contains:

* `sfuzz.py` — main Python script (the tool you provided)
* `install_ollama.sh` — Ollama auto-installer (bash)
* `wordlists/` — subdomain and directory wordlists
* `README.md` — this document
* `tools/` — optional external tools and integrations (see below)

---

---

## Features

### AI-Powered Core
* 4 Distinct Scanning Modes:
  - Fast: Quick reconnaissance
  - Smart: Balanced scanning
  - Aggressive: Deep enumeration
  - Deep: Maximum discovery

* Intelligent Pattern Recognition:
  - Self-learning subdomain patterns
  - Adaptive scan behavior
  - Dynamic wordlist generation
  - Context-aware scanning

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

## Installation

### Prerequisites
* Python 3.8+
* pip for Python package installation
* Optional: Ollama for enhanced AI features

### Quick Start

```bash
# Clone the repository
git clone https://github.com/cyberhulk99/SubFuzz.git
cd SubFuzz

# Install required packages
pip install -r requirements.txt

# Optional: Install Ollama for AI features
chmod +x install_ollama.sh
./install_ollama.sh
```

### Optional Components

1. **Nuclei Integration**: 
   - Follow official docs at `https://github.com/projectdiscovery/nuclei`

2. **Ollama Setup (for AI features)**:
   - Automated: Use provided `install_ollama.sh`
   - Manual: Follow instructions at `https://ollama.ai`

3. **External Tools Integration**:
   - Place external tools in the `tools/` directory
   - Enable via appropriate CLI flags
   - See Integration Tips section for best practices

### Wordlists

You can use wordlists in two ways:

1. **Using Custom Wordlists (Recommended)**:
   - Use any wordlist directly with the `-w` flag:
     ```bash
     python3 sfuzz.py -d example.com -w /path/to/your/wordlist.txt
     ```
   - This gives you flexibility to use your preferred wordlists

2. **Default Wordlists (Optional)**:
   - The tool can also use wordlists from the `wordlists/` directory
   - For subdomain scanning: `wordlists/subdomains/`
   - For directory scanning: `wordlists/dirs/`
   - Example with default location:
     ```bash
     # If you want to use the default location, just place your list here:
     mkdir -p wordlists/subdomains
     cp your-wordlist.txt wordlists/subdomains/
     ```

Note: You're not limited to any specific wordlist. The tool is designed to work with any text-based wordlist through the `-w` flag.

---

## Roadmap & Coming Soon

🚀 **Upcoming Features:**

* Advanced vulnerability assessment modules
* Enhanced smart rate limiting system
* Comprehensive security header analysis
* Automated reporting system
* Performance benchmarking
* Advanced AI features
* Scan resumption capability

These features are actively being developed. Stay tuned for updates!

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

* Keep external tools in `tools/` and refer to them from the main script
* Use appropriate CLI flags to enable/disable integrations
* Follow modular design patterns for new integrations

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

Your feedback and contributions are welcome! Particularly interested in:
* Real-world testing scenarios
* Performance optimization ideas
* Feature suggestions
* Security research use cases

---

## Security Notice

* Run only against systems you own or have explicit permission to test
* Use `--stealth` mode for careful scanning
* Consider rate limiting for production systems
* Review and respect target system's security policies

---

## License

MIT © @cyberhulk99

---

## Connect & Contribute

* GitHub: [@cyberhulk99](https://github.com/cyberhulk99)
* Issues/Features: [Issue Tracker](https://github.com/cyberhulk99/SubFuzz/issues)
* Join the discussion: [Discussions](https://github.com/cyberhulk99/SubFuzz/discussions)

From non-tech to security tooling - Let's make security tools smarter together! 🛡️

---

## Changelog (high-level)

* v1.0.1 — Documentation & Usability Improvements:
  - Added flexible wordlist support with -w flag
  - Improved documentation organization and clarity
  - Enhanced usage examples and installation guide
  - Consolidated feature documentation
  - Added integration guidelines
  - Updated command-line options documentation

* v1.0.0 — Initial Release with Advanced Features:
  - Implemented AISubdomainAnalyzer with pattern learning
  - Enhanced AIPenetrationSystem with Ollama integration
  - Added comprehensive JavaScript reconnaissance
  - Advanced technology stack detection
  - Intelligent directory scanning with AI path prediction
  - Multi-source passive reconnaissance
  - Enhanced active enumeration capabilities
