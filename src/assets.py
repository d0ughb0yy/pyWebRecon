import os
import tempfile
from urllib.parse import urlparse
from src.commands import (
    crtshRequest,
    subfinderExec,
    purednsExec,
    bbotExec,
    waymoreExec,
    dnsxExec,
    httpxExec,
)
from src.output import runToolsParallel, console


def urlsToSubdomains(urls: set[str], target_domain: str) -> set[str]:
    """Extract subdomains from a set of URLs, filtering to the target domain."""
    subdomains = set()
    target_domain = target_domain.lower()
    for url in urls:
        try:
            hostname = urlparse(url).hostname
            if hostname:
                hostname = hostname.lower()
                if hostname == target_domain or hostname.endswith(f".{target_domain}"):
                    subdomains.add(hostname)
        except Exception:
            continue
    return subdomains


def subdomainEnumeration(target_domain, wordlists):
    """Passive and active gathering workflow using multiple subdomain tools.

    This function runs multiple subdomain enumeration tools concurrently:
    - crt.sh: Certificate transparency logs
    - subfinder: Passive subdomain discovery
    - puredns: DNS bruteforce with wildcard filtering via massdns
    - bbot: Comprehensive subdomain enumeration (passive + active)
    - waymore: URL discovery from archive sources (outputs to file only)

    Args:
        target_domain: Target domain for enumeration
        wordlists: List of wordlist file paths to combine for puredns

    Returns:
        set: Aggregated set of all discovered subdomains
    """
    console.print("\n[bold green]Gathering Subdomains[/bold green]\n")

    # Combine all wordlists into a single temp file
    combined_wordlist_path = None
    if wordlists:
        all_words = set()
        for wl in wordlists:
            with open(wl, "r") as f:
                for line in f:
                    word = line.strip()
                    if word:
                        all_words.add(word)

        # Write combined, deduplicated wordlist to temp file
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as tmp:
            for word in all_words:
                tmp.write(f"{word}\n")
            combined_wordlist_path = tmp.name

    try:
        tools = {
            "crt.sh": (crtshRequest, (target_domain,)),
            "subfinder": (subfinderExec, (target_domain,)),
            "bbot": (bbotExec, (target_domain,)),
            "waymore": (waymoreExec, (target_domain,)),
        }

        if combined_wordlist_path:
            tools["puredns"] = (purednsExec, (target_domain, combined_wordlist_path))

        # Run tools concurrently and get results
        results = runToolsParallel(tools)

        # Aggregate all subdomains from tool results
        all_subdomains = set()
        for tool_name, tool_result in results.items():
            if isinstance(tool_result, set):
                if tool_name == "waymore":
                    all_subdomains.update(urlsToSubdomains(tool_result, target_domain))
                else:
                    all_subdomains.update(tool_result)

        return all_subdomains
    finally:
        # Clean up temp file
        if combined_wordlist_path and os.path.exists(combined_wordlist_path):
            os.unlink(combined_wordlist_path)


def processingSubdomains(target_domain, all_subdomains):
    """Process subdomains by resolving and scanning with httpx.

    This function performs two sequential operations:
    1. Resolve subdomains using dnsx
    2. Scan resolved domains with httpx to gather HTTP metadata

    Args:
        target_domain: The target domain to scan
        all_subdomains: Set of subdomains to process
    """
    console.print("\n[bold green]Processing subdomains[/bold green]\n")

    # Resolve subdomains using runToolsParallel for consistent status display
    tools_dnsx = {
        "dnsx": (dnsxExec, (all_subdomains, target_domain, "dnsx_resolved.txt"))
    }
    results = runToolsParallel(tools_dnsx)
    resolved_domains = results.get("dnsx", set())

    # Run httpx scan on resolved domains using runToolsParallel
    if resolved_domains:
        tools_httpx = {
            "httpx": (httpxExec, (resolved_domains, target_domain, "httpx_scan.txt"))
        }
        runToolsParallel(tools_httpx)
    else:
        console.print("[yellow]No subdomains resolved — skipping HTTP probe[/yellow]")
