# AGENTS.md - Bug Bounty Recon Script

## Commands

### Run Script
```bash
python3 pywebrecon.py -d <target-domain> -w <wordlist1> [wordlist2 ...]
```

### Testing
```bash
python3 pywebrecon.py -d example.com -w /path/to/small.txt
python3 pywebrecon.py -d example.com -w /path/to/small.txt /path/to/large.txt
```

Verify Rich output is working:
```bash
python3 -c "from src.output import console; console.print('[green]Rich is working![/green]')"
```

## Dependencies

### Python Packages
```
rich>=13.0.0
```

### External Tools
Install via package manager or GitHub releases:
- `subfinder` - Subdomain discovery
- `shuffledns` - DNS bruteforcing (requires resolvers at `~/.config/shuffledns/resolvers.txt`, resolved via `Path.home()`)
- `dnsx` - DNS resolution
- `httpx` - HTTP probing

## Architecture

```
pywebrecon.py      # CLI entry point
src/
├── commands.py    # External tool wrappers (raise exceptions on failure)
├── assets.py      # Workflow orchestration with live status display
└── output.py      # Console helpers and results display
```

## Code Style

### Imports
- Group: stdlib (os, json, time), then external, then local
- Use absolute imports from `src/` modules
- Use explicit imports: `from src.assets import subdomainEnumeration`

### Naming
- Functions: `camelCase` (e.g., `dnsxExec`, `subdomainEnumeration`)
- Files: `snake_case.py`
- Variables: `snake_case`
- Constants: UPPER_CASE (if any)

### Formatting
- Black formatter as vscode extension
- Use 4-space indentation
- Keep lines under 100 characters when possible

### Output Functions
Use Rich console output helpers from `src/output.py`:
```python
from src.output import info, error

info("Process complete!")     # ✅ style - green bold
error("Process failed!")      # ❗ style - red bold
```

### Error Handling
Tools raise exceptions on failure:
```python
def tool_exec(args):
    result = subprocess.run(cmd, ...)
    if result.returncode != 0:
        raise Exception(f"tool failed: {result.stderr.decode()}")
```

Exceptions are caught by `runToolsParallel()` and displayed in the execution summary.

### Concurrency
- Use `concurrent.futures.ThreadPoolExecutor` for parallel execution
- `runToolsParallel` handles the full lifecycle (submit, wait, collect results)
- Returns dict mapping tool names to their return values (sets)

### Live Status Pattern
```python
from src.output import runToolsParallel

tools = {
    "tool-1": (tool1_func, (arg1, arg2)),
    "tool-2": (tool2_func, (arg3,)),
}

results = runToolsParallel(tools)
```

### File Paths
- Use `pathlib.Path` for path operations
- Output directory: `{target_domain}/domain-recon/`
- Use `tempfile.NamedTemporaryFile` for temporary files (auto-cleaned)

### Output Files
- `dnsx_resolved.txt` - resolved subdomains
- `httpx_scan.txt` - HTTP probe results

### Temp File Cleanup
- `tempfile.NamedTemporaryFile(delete=True)` for tool input files
- Combined wordlist temp file cleaned in `finally` block

## Visual Output

### Live Status Display
During execution, live text displays concurrent tools:

```
⏳ crt.sh pending
⏳ subfinder pending
⏳ shuffledns pending

⏳ crt.sh running...
✅ crt.sh COMPLETED 14:32:01
⏳ subfinder running...
✅ subfinder COMPLETED 14:32:05
...
```

**Status Lifecycle:**
- `⏳ {tool} pending` (yellow) - Tool waiting to start
- `⏳ {tool} running...` (cyan) - Tool currently executing
- `✅ {tool} COMPLETED HH:MM:SS` (green) - Tool finished successfully
- `❌ {tool} FAILED HH:MM:SS` (red) - Tool encountered an error

**Note:** Execution Summary is only printed if any tools failed.

## Workflow

```
subdomainEnumeration() → processingSubdomains()
```

1. **Subdomain Enumeration** (concurrent): crt.sh + subfinder + shuffledns
   - Wordlists are combined (deduplicated) into a single temp file
   - All tools run concurrently with live status display
   - Results aggregated into a single in-memory set

2. **Processing Subdomains** (sequential):
   - Resolve subdomains via dnsx → writes `dnsx_resolved.txt`
   - Scan resolved domains via httpx → writes `httpx_scan.txt`

3. **Cleanup**: Combined wordlist temp file removed

## Key Implementation Details

### Live Status Updates
- `LiveStatus` class stores `Rich.Text` objects per tool
- Uses `Group` to render all status lines together
- Status updated in-place: `self.status[tool_name] = Text(new_text, style=style)`
- `Live` display auto-refreshes at 4Hz

### Error Handling in Live Status
Failed tools show red status in display:
```
❌ shuffledns FAILED 14:32:10
```

Error details printed in Execution Summary (only if failures occur):
```
❗ shuffledns: <error message>
```

### Tool Return Values
All tool functions return sets of subdomains:
- `subfinderExec`, `crtshRequest`, `shufflednsExec` → return `set[str]`
- `dnsxExec` → returns `set[str]` (resolved domains)
- `httpxExec` → returns empty `set()` (writes file, result not needed downstream)

### Temp File Strategy
- Tool input files use `tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=True)`, flushed before passing to CLI tools
- Combined wordlist uses `tempfile.NamedTemporaryFile(delete=False)` (needs to persist for the duration of shuffledns), manually `os.unlink()` in `finally`

## Safety Notes

- Only run against domains you have permission to test
- Tools perform active DNS queries and HTTP requests
- Rate limiting applied where possible (httpx `-rl 50`)
