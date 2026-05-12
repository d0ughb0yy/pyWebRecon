# pyWebRecon

A Python-based subdomain reconnaissance automation framework designed for bug bounty hunting and security assessments. Built to demonstrate concurrent programming, Docker orchestration, and CLI UX design patterns.

## What It Does

pyWebRecon automates the subdomain discovery process by orchestrating multiple industry-standard security tools via Docker into a single, cohesive pipeline. Instead of running each tool manually and stitching results together, this framework handles the entire workflow—from passive enumeration to active scanning—in one command.

## Key Features

**Multi-Tool Orchestration**
- Integrates 6 security tools (subfinder, shuffledns, bbot, dnsx, httpx, crt.sh API)
- All tools run via Docker containers — zero local dependencies beyond Docker
- Containers are named after their tool (`docker ps` shows `dnsx`, `httpx`, etc.)
- Handles tool dependencies and execution order automatically

**Concurrent Execution**
- Multi-threaded tool execution for performance
- Live status monitoring with emoji indicators and timestamps
- Real-time progress updates with visual feedback

## Installation

### Prerequisites
```bash
# Docker (required)
# https://docs.docker.com/engine/install/

# Python 3.9+
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

*Only requirement: `rich>=13.0.0`*

### Docker Images (pulled automatically on first run)
- `projectdiscovery/subfinder:latest` — Passive subdomain discovery
- `projectdiscovery/shuffledns:latest` — DNS bruteforce
- `projectdiscovery/dnsx:latest` — DNS resolution
- `projectdiscovery/httpx:latest` — HTTP probing
- `blacklanternsecurity/bbot:latest` — Comprehensive subdomain enumeration

### Required Local Files
- `~/.config/subfinder/config.yaml` — API keys for subfinder
- `~/.config/shuffledns/resolvers.txt` — DNS resolvers for shuffledns (Won't run without it)
- `~/.config/bbot/bbot.yml` + `~/.config/bbot/secrets.yml` — API keys for bbot

## Usage

```bash
python3 pywebrecon.py -d <target-domain> -w <wordlist> [wordlist2] [wordlist3] ...
```

### Examples
```bash
# Single wordlist
python3 pywebrecon.py -d example.com -w /path/to/subdomains.txt

# Multiple wordlists (combined into single shuffledns process)
python3 pywebrecon.py -d example.com \
  -w /path/to/small.txt /path/to/large.txt
```

## Technical Highlights

**Key Implementation Details:**
- **Docker Orchestration**: All tools run as Docker containers with named instances (`--name`), auto-removed on exit (`--rm`)
- **Live Status Display**: Uses Rich's `Live` display with emoji indicators for pending (⏳), running, completed (✅), and failed (❌) tasks
- **File Ownership**: DNS resolution and HTTP probing containers run with `--user $(id -u):$(id -g)` so output files are owned by you
- **Config Persistence**: BBot mounts `~/.bbot/` to persist cached wordlists and tool data between runs
- **Memory Efficient**: Collects tool outputs as in-memory sets for fast aggregation; final results written to disk
- **Rate Limiting**: httpx configured with `-rl 50` to be respectful to target infrastructure

## Why This Project?

I built pyWebRecon to solve a problem for myself: manually running and correlating results from multiple subdomain tools is tedious and error-prone. This framework demonstrates:

1. **Systems Programming**: Integrating external CLI tools into Python applications via Docker
2. **Concurrent Design**: Managing shared state across threads safely
3. **User Experience**: Making command-line tools feel polished and professional
4. **Security Domain Knowledge**: Understanding the bug bounty reconnaissance workflow
