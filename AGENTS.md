# AGENTS.md - pyWebRecon

## Run Command
```bash
python3 pywebrecon.py -d <target-domain> -w <wordlist1> [wordlist2] [wordlist3]...
```
- `-w` accepts one or more wordlists (combined into single shuffledns process)
- Wordlists validated at startup: must exist, be readable, and non-empty
- Domain format validated at startup (basic pattern check)

## Dependencies

### Python
```
rich>=13.0.0
```

### External Tools
- `subfinder` - Passive subdomain discovery
- `shuffledns` - DNS bruteforce (requires `~/.config/shuffledns/resolvers.txt`)
- `dnsx` - DNS resolution
- `httpx` - HTTP probing (rate limited to 50)
- `bbot` - Passive subdomain enumeration

## Architecture
```
pywebrecon.py        # CLI entry point, argparse
src/
├── commands.py      # Tool wrappers (raise exceptions on failure)
├── assets.py        # Workflow orchestration
└── output.py        # Rich console helpers, live status display
```

## Workflow
```
subdomainEnumeration() → processingSubdomains() → cleanup()
```

1. **subdomainEnumeration**: crt.sh + subfinder + bbot + shuffledns (concurrent)
2. **processingSubdomains**: dnsx → httpx (sequential)
3. **cleanup**: Remove BBOT scan directory (`~/.bbot/scans/{target}/`)

## Output Files
Only these files are created in `{target}/domain-recon/`:
- `dnsx_resolved.txt` - Resolved subdomains
- `httpx_scan.txt` - HTTP probe results

## Code Style

### Imports
Use explicit imports (no wildcards):
```python
# pywebrecon.py
from src.assets import subdomainEnumeration, processingSubdomains, cleanup
from src.output import info, console

# src/assets.py
from src.commands import crtshRequest, subfinderExec, bbotExec, shufflednsExec, dnsxExec, httpxExec
from src.output import runToolsParallel, error, console
```

### Naming
- Functions: `camelCase` (e.g., `dnsxExec`, `subdomainEnumeration`)
- Files: `snake_case.py`
- Variables: `snake_case`

### Output Helpers
```python
from src.output import info, error, console
info("Starting...")    # [+] green
error("Failed!")       # [!] red
```

## Live Status Pattern
```python
from src.output import runToolsParallel

tools = {
    "tool-name": (tool_func, (arg1, arg2)),
}
results = runToolsParallel(tools)
```
- Uses Rich `Live` display at 4Hz
- Tools run concurrently via `concurrent.futures.ThreadPoolExecutor`
- Exceptions caught and shown in Execution Summary

## Error Handling
Tools raise exceptions on failure:
```python
result = subprocess.run(..., timeout=1800)
if result.returncode != 0:
    raise Exception(f"tool failed: {result.stderr.decode()}")
```
- All subprocess calls have 30-minute timeout (1800s)
- Caught by `runToolsParallel()`, displayed in table and execution summary

## BBOT Integration
```bash
bbot -t <target> -p subdomain-enum -rf passive -n <target> -om subdomains -o <temp_dir> -y -s
```
- Passive only (`-rf passive`)
- Output extracted from `<temp_dir>/subdomains.txt`
- Temp directory cleaned up after extraction
- BBOT scan dir `~/.bbot/scans/{target}/` cleaned by `cleanup()`

## Key Implementation Details

### dnsxExec / httpxExec
- Use `tempfile.NamedTemporaryFile` for input (delete=True)
- Write output directly to target directory
- Return sets for aggregation (httpxExec returns empty set)

### shufflednsExec
- Hardcoded resolvers path: `/home/d0b0/.config/shuffledns/resolvers.txt`
- Returns subdomains via stdout parsing (not file)

### crtshRequest
- HTTP GET to `https://crt.sh/?q={domain}&output=json`
- Chrome User-Agent with humanlike headers
- Retries 5 times with exponential backoff (2s → 4s → 8s → 16s → 32s)
- Filters domains ending with target

### subdomainEnumeration
- Wordlists combined into temp file using set for deduplication
- Temp file cleanup guaranteed via `try/finally`
- `shutil` imported at module level (not locally)

## Safety Notes
- Only run against domains you have permission to test
- httpx uses `-rl 50` rate limiting
- BBOT passive mode avoids active probes
- All external tool calls have 30-minute timeout to prevent hangs