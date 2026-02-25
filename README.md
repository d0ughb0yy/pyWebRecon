# pyWebRecon

A Python-based subdomain reconnaissance automation framework designed for bug bounty hunting and security assessments. Built to demonstrate concurrent programming, system integration, and CLI UX design patterns.

## What It Does

pyWebRecon automates the subdomain discovery process by orchestrating multiple industry-standard security tools into a single, cohesive pipeline. Instead of running each tool manually and stitching results together, this framework handles the entire workflow—from passive enumeration to active scanning—in one command.

## Key Features

**Multi-Tool Orchestration**
- Integrates 6+ security tools (subfinder, httpx, shuffledns, dnsx, alterx, bbot, crt.sh API)
- Handles tool dependencies and execution order automatically
- Intelligent error handling with per-tool status tracking

**Concurrent Execution**
- Multi-threaded tool execution for performance
- Live status monitoring with text-based display
- Real-time progress updates with emoji indicators and timestamps

**Developer-Friendly UX**
- Clean, colorful terminal output using Rich library
- Visual status display showing pending/running/completed/failed states
- Detailed error reporting without cluttering successful runs

**Smart Cleanup**
- Automatically removes intermediate files
- Preserves only consolidated results (resolved domains + HTTP probe data)
- Maintains clean output directories

## Installation

### Prerequisites
```bash
# External tools (install via package manager or GitHub releases)
subfinder      # Subdomain discovery
httpx          # HTTP probing
shuffledns     # DNS bruteforce
dnsx           # DNS resolution
alterx         # Subdomain permutation
anew           # File appending utility
bbot           # Comprehensive subdomain enumeration
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

*Only requirement: `rich>=13.0.0`*

## Usage

```bash
python3 pywebrecon.py -d <target-domain> -fw <wordlist> [-sw <wordlist2>]
```

### Examples
```bash
# Single wordlist
python3 pywebrecon.py -d example.com -fw /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Dual wordlists
python3 pywebrecon.py -d example.com \
  -fw /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -sw /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

## Workflow Pipeline

The framework executes reconnaissance in **3 sequential stages**, with concurrent tool execution within each stage:

### 1. Subdomain Enumeration (Concurrent)
| Tool | Purpose |
|------|---------|
| **crt.sh** | Certificate transparency logs |
| **subfinder** | Passive subdomain discovery |
| **bbot** | Multi-source passive enumeration |
| **shuffledns** (1-2) | DNS bruteforce with wordlists |

### 2. Resolving and Permutation
- Resolves all discovered subdomains using **dnsx**
- Generates subdomain variations with **alterx**
- Resolves permutations and appends valid ones to results

### 3. HTTP Probing
- Probes all resolved domains with **httpx**
- Captures status codes, redirects, server headers, titles, and CDN info

## Output

After execution, you'll find two files in `{domain}/domain-recon/`:

| File | Contents |
|------|----------|
| `dnsx_all_resolved.txt` | All resolved subdomains (one per line) |
| `httpx_dnsx_all_resolved_scan.txt` | HTTP probe results with metadata |

Intermediate files are automatically cleaned up.

## Technical Highlights

**Built With:**
- Python 3.8+ (type hints, pathlib, threading)
- [Rich](https://github.com/Textualize/rich) for terminal UI
- Subprocess management for external tool integration

**Key Implementation Details:**
- **Live Status Display**: Uses Rich's `Live` display with text-based status updates
- **Error Resilience**: Tools raise exceptions on failure; caught and displayed without crashing pipeline
- **Memory Efficient**: Streams tool outputs directly to files, minimal in-memory data storage
- **Rate Limiting**: httpx configured with `-rl 50` to be respectful to target infrastructure

## Why This Project?

I built pyWebRecon to solve a problem for myself: manually running and correlating results from multiple subdomain tools is tedious and error-prone. This framework demonstrates:

1. **Systems Programming**: Integrating external CLI tools into Python applications
2. **Concurrent Design**: Managing shared state across threads safely
3. **User Experience**: Making command-line tools feel polished and professional
4. **Security Domain Knowledge**: Understanding the bug bounty reconnaissance workflow

It's designed to be **hackable**, each stage is modular, so adding new tools or changing the workflow is straightforward.