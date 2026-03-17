from pathlib import Path
from datetime import datetime
from src.commands import *
from src.output import runToolsParallel, error, console


def subdomainEnumeration(target_domain, first_wordlist, second_wordlist):
    """Passive and active gathering workflow using crtsh, subfinder, shuffledns, and bbot.
    
    This function runs multiple subdomain enumeration tools concurrently:
    - crt.sh: Certificate transparency logs
    - subfinder: Passive subdomain discovery
    - bbot: Multi-source passive enumeration
    - shuffledns: DNS bruteforce with wordlists (1-2 wordlists supported)
    
    Returns:
        set: Aggregated set of all discovered subdomains
    """
    console.print("\n[bold green]Gathering Subdomains...[/bold green]\n")

    tools = {
        "crt.sh": (crtshRequest, (target_domain,)),
        "subfinder": (subfinderExec, (target_domain,)),
        "bbot": (bbotExec, (target_domain,)),
        "shuffledns-1": (shufflednsExec, (target_domain, first_wordlist)),
    }
    
    if second_wordlist:
        tools["shuffledns-2"] = (shufflednsExec, (target_domain, second_wordlist))
    
    # Run tools concurrently and get results
    results = runToolsParallel(tools)
    
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


def permutateSubdomains(target_domain, resolved_domains):
    """Permutate subdomains, resolve them, and scan with httpx.
    
    This function performs three sequential operations:
    1. Generate subdomain permutations using alterx
    2. Resolve permutated domains using dnsx
    3. Scan resolved permutated domains with httpx
    
    Args:
        target_domain: The target domain to scan
        resolved_domains: Set of resolved subdomains from previous stage
    """
    console.print("\n[bold green]Permutating subdomains[/bold green]\n")
    
    # Generate permutations using runToolsParallel for consistent status display
    tools_alterx = {
        "alterx": (alterxExec, (resolved_domains,))
    }
    results = runToolsParallel(tools_alterx)
    permutated_domains = results.get("alterx", set())
    
    if permutated_domains:
        # Resolve permutated domains using runToolsParallel
        tools_dnsx = {
            "dnsx-permutated": (dnsxExec, (permutated_domains, target_domain, "dnsx_permutated_resolved.txt"))
        }
        results = runToolsParallel(tools_dnsx)
        resolved_perm_domains = results.get("dnsx-permutated", set())
        
        # Run httpx scan on permutated domains using runToolsParallel
        if resolved_perm_domains:
            tools_httpx = {
                "httpx-permutated": (httpxExec, (resolved_perm_domains, target_domain, "httpx_permutated_scan.txt"))
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