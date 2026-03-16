from pathlib import Path
from src.commands import *
from src.output import runToolsParallel, error, console


def subdomainEnumeration(target_domain, first_wordlist, second_wordlist):
    """Passive and active gathering workflow using crtsh, subfinder, shuffledns, and bbot.
    
    This function runs multiple subdomain enumeration tools concurrently:
    - crt.sh: Certificate transparency logs
    - subfinder: Passive subdomain discovery
    - bbot: Multi-source passive enumeration
    - shuffledns: DNS bruteforce with wordlists (1-2 wordlists supported)
    """
    console.print("\n[bold green]Gathering Subdomains...[/bold green]\n")
    first_wordlist_name = Path(first_wordlist).stem
    second_wordlist_name = Path(second_wordlist).stem if second_wordlist else None

    tools = {
        "crt.sh": (crtshRequest, (target_domain,)),
        "subfinder": (subfinderExec, (target_domain,)),
        "bbot": (bbotExec, (target_domain,)),
        "shuffledns-1": (shufflednsExec, (target_domain, first_wordlist, f"shuffledns_{first_wordlist_name}_output.txt")),
    }
    
    if second_wordlist:
        tools["shuffledns-2"] = (shufflednsExec, (target_domain, second_wordlist, f"shuffledns_{second_wordlist_name}_output.txt"))
    
    runToolsParallel(tools)

    bbotExtractAndAppend(target_domain)

    source_files = ["subfinder_output.txt", "crtsh_output.txt", 
                    f"shuffledns_{first_wordlist_name}_output.txt"]
    if second_wordlist:
        source_files.append(f"shuffledns_{second_wordlist_name}_output.txt")
    
    for src in source_files:
        anewExec(f"{target_domain}/domain-recon/{src}", f"{target_domain}/domain-recon/all_subs.txt")


def processingSubdomains(target_domain):
    """Process subdomains by resolving and scanning with httpx.
    
    This function performs two sequential operations:
    1. Resolve subdomains from all_subs.txt using dnsx
    2. Scan resolved domains with httpx to gather HTTP metadata
    
    Output files:
    - dnsx_resolved.txt: Resolved subdomains
    - httpx_scan.txt: HTTP probe results with status codes, titles, etc.
    """
    console.print("\n[bold green]Processing subdomains[/bold green]\n")
    
    # Resolve subdomains
    tools = {
        "dnsx": (dnsxExec, ("all_subs.txt", "dnsx_resolved.txt", target_domain)),
    }
    runToolsParallel(tools)
    
    # Run httpx scan on resolved domains
    tools_httpx = {
        "httpx": (httpxExec, (target_domain, f"{target_domain}/domain-recon/dnsx_resolved.txt", "httpx_scan.txt")),
    }
    runToolsParallel(tools_httpx)


def permutateSubdomains(target_domain):
    """Permutate subdomains, resolve them, and scan with httpx.
    
    This function performs three sequential operations:
    1. Generate subdomain permutations using alterx
    2. Resolve permutated domains using dnsx
    3. Scan resolved permutated domains with httpx
    
    Output files:
    - dnsx_permutated_resolved.txt: Resolved permutated subdomains
    - httpx_permutated_scan.txt: HTTP probe results for permutated domains
    """
    console.print("\n[bold green]Permutating subdomains[/bold green]\n")
    
    # Generate permutations
    tools1 = {
        "alterx": (alterxExec, (target_domain,)),
    }
    runToolsParallel(tools1)
    
    # Resolve permutated domains
    tools2 = {
        "dnsx-permutated": (dnsxExec, ("permutated_subs_output.txt", "dnsx_permutated_resolved.txt", target_domain)),
    }
    runToolsParallel(tools2)
    
    # Run httpx scan on permutated domains
    tools_httpx = {
        "httpx": (httpxExec, (target_domain, f"{target_domain}/domain-recon/dnsx_permutated_resolved.txt", "httpx_permutated_scan.txt")),
    }
    runToolsParallel(tools_httpx)


def cleanup(target_domain):
    """Remove intermediate files while preserving final results.
    
    Preserved files:
    - dnsx_resolved.txt: Normal resolved subdomains
    - dnsx_permutated_resolved.txt: Permutated resolved subdomains
    - httpx_scan.txt: HTTP scan results for normal domains
    - httpx_permutated_scan.txt: HTTP scan results for permutated domains
    
    Removed files:
    - Intermediate tool outputs (*_output.txt, permutated_*, etc.)
    - Aggregated subdomain list (all_subs.txt)
    - BBOT scan directory
    """
    directory = Path(f"{target_domain}/domain-recon/")
    # Keep: dnsx_resolved.txt, dnsx_permutated_resolved.txt, httpx_scan.txt, httpx_permutated_scan.txt
    # Remove: *_output.txt, permutated_*, all_subs.txt, bbot_*, crtsh_output.txt, subfinder_output.txt, shuffledns_*
    for pattern in ["*_output.txt", "permutated_*", "all_subs.txt", "bbot_*", "crtsh_output.txt", "subfinder_output.txt", "shuffledns_*"]:
        for file_path in directory.glob(pattern):
            if file_path.is_file():
                try:
                    file_path.unlink()
                except Exception as e:
                    error(f"Error deleting {file_path}: {e}")
    
    bbotScanDir = Path.home() / f".bbot/scans/{target_domain}"
    if bbotScanDir.exists():
        import shutil
        try:
            shutil.rmtree(bbotScanDir)
        except Exception as e:
            error(f"Error deleting BBOT scan directory: {e}")
