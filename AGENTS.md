# AGENTS.md

## Commands

```bash
python3 pywebrecon.py -d <domain> -w <wordlist1> [wordlist2 ...]
```

No test/lint/typecheck framework configured. Validate by running against a test domain.

## Required host files (must pre-exist)

- `~/.config/subfinder/config.yaml` — mounted read-only into subfinder container at `/root/.config/subfinder/config.yaml`
- `~/.config/shuffledns/resolvers.txt` — mounted read-only into shuffledns container
- `~/.config/bbot/bbot.yml` + `~/.config/bbot/secrets.yml` — mounted read-write into bbot container (bbot writes temp files to config dir)
- `~/.bbot/` — created if missing, mounted into bbot container to persist cache/wordlists/tools
- `~/.config/waymore/config.yml` — waymore config with API keys and filters (must be installed via pipx)

## Key architecture

```
pywebrecon.py → src/assets.py → src/commands.py (Docker wrappers)
                              → src/output.py  (live display)
```

### Workflow

1. **subdomainEnumeration** (concurrent via `ThreadPoolExecutor`): crt.sh, subfinder, bbot, shuffledns, waymore
   - Results aggregated into a single `set[str]`
   - bbot runs with `-p subdomain-enum -rf passive` (passive-only, uses API keys from config)
   - waymore runs in mode `U` (URLs only), outputs to `{domain}/domain-recon/waymore_urls.txt`
2. **processingSubdomains** (sequential): dnsx → httpx
   - httpx only runs if dnsx resolved at least one domain

### Docker orchestration quirks

- All containers use `--name <tool>` so they appear in `docker ps`.
- `dnsx` and `httpx` use `--user $(id -u):$(id -g)` so output files are owned by host user.
- `subfinder`, `shuffledns`, `bbot` do NOT use `--user` (they only emit stdout, no host file writes).
- Temp input files: `NamedTemporaryFile(delete=True)` for dnsx/httpx input. Combined wordlist for shuffledns uses `delete=False` and is manually `os.unlink()`ed in a `finally` block.
- bb timeout: 3600s (comprehensive). All others: 1800s.
- waymore is NOT a Docker tool — it's installed via pipx and runs as a native subprocess. It checks for the `waymore` binary at runtime and raises `FileNotFoundError` if missing.

### Output files

All written to `{domain}/domain-recon/`:
- `dnsx_resolved.txt` — resolved subdomains (read back into memory for httpx input)
- `httpx_scan.txt` — HTTP probe results (written only, not read back)
- `waymore_urls.txt` — URLs discovered from archive sources (written only, not read back)

### runToolsParallel contract

```python
tools = {
    "display-name": (func_ref, (arg1, arg2)),
}
results = runToolsParallel(tools)  # returns dict[str, set[str]]
```

Inside the `runTool` closure, exceptions are caught and displayed as red ❌ in the live status. The exception is swallowed (not re-raised) — failures update the display but don't crash the pipeline. The return dict only contains entries for tools that succeeded.

## Docker images

| Image | Tool | Purpose |
|---|---|---|
| `projectdiscovery/subfinder:latest` | subfinder | Passive subdomain discovery |
| `projectdiscovery/shuffledns:latest` | shuffledns | DNS bruteforce |
| `projectdiscovery/dnsx:latest` | dnsx | DNS resolution |
| `projectdiscovery/httpx:latest` | httpx | HTTP probing |
| `blacklanternsecurity/bbot:latest` | bbot | Comprehensive subdomain enum (passive only) |

## Naming conventions

- Functions: `camelCase` (e.g. `dnsxExec`, `subdomainEnumeration`, `waymoreExec`)
- Files: `snake_case.py`
- Imports: stdlib → external (rich) → local (`src.`), absolute only
