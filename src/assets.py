from pathlib import Path
from datetime import datetime
import tempfile
import os
from src.commands import *
from src.output import runToolsParallel, error, console


def subdomainEnumeration(target_domain, wordlists):
    """Passive and active gathering workflow using crtsh, subfinder, shuffledns, and bbot.
    
    This function runs multiple subdomain enumeration tools concurrently:
    - crt.sh: Certificate transparency logs
    - subfinder: Passive subdomain discovery
    - bbot: Multi-source passive enumeration
    - shuffledns: DNS bruteforce with combined wordlists (single process)
    
    Args:
        target_domain: Target domain for enumeration
        wordlists: List of wordlist file paths to combine for shuffledns
    
    Returns:
        set: Aggregated set of all discovered subdomains
    """
    console.print("\n[bold green]Gathering Subdomains...[/bold green]\n")

    # Combine all wordlists into a single temp file
    combined_wordlist_path = None
    if wordlists:
        all_words = set()
        for wl in wordlists:
            with open(wl, 'r') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        all_words.add(word)
        
        # Write combined, deduplicated wordlist to temp file
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as tmp:
            for word in all_words:
                tmp.write(f"{word}\n")
            combined_wordlist_path = tmp.name

    tools = {
        "crt.sh": (crtshRequest, (target_domain,)),
        "subfinder": (subfinderExec, (target_domain,)),
        "bbot": (bbotExec, (target_domain,)),
    }
    
    if combined_wordlist_path:
        tools["shuffledns"] = (shufflednsExec, (target_domain, combined_wordlist_path))
    
    # Run tools concurrently and get results
    results = runToolsParallel(tools)
    
    # Clean up temp file
    if combined_wordlist_path and os.path.exists(combined_wordlist_path):
        os.unlink(combined_wordlist_path)
    
    # Aggregate all subdomains from tool results
    all_subdomains = set()
    for tool_name, tool_result in results.items():
        if isinstance(tool_result, set):
            all_subdomains.update(tool_result)
    
    return all_subdomains


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


def cleanup(target_domain):
    """Cleanup temporary files and external scan directories.
    """
    # Clean up BBOT scan directory in home directory
    bbotScanDir = Path.home() / f".bbot/scans/{target_domain}"
    if bbotScanDir.exists():
        import shutil
        try:
            shutil.rmtree(bbotScanDir)
        except Exception as e:
            error(f"Error deleting BBOT scan directory: {e}")