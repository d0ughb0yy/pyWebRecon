from pathlib import Path
from src.commands import *
from src.output import runToolsParallel, error, console


def subdomainEnumeration(target_domain, first_wordlist, second_wordlist):
    """Passive and active gathering workflow using crtsh, subfinder, shuffledns, and bbot."""
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


def subdomainResolvePermute(target_domain):
    """Resolve and permutate subdomains with dnsx and alterx."""
    console.print("\n[bold green]Resolving and Permutation[/bold green]\n")

    tools = {
        "dnsx": (dnsxExec, ("all_subs.txt", "dnsx_all_resolved.txt", target_domain)),
    }
    runToolsParallel(tools)

    tools1 = {
        "alterx": (alterxExec, (target_domain,)),
    }
    runToolsParallel(tools1)

    tools2 = {
        "dnsx-permutated": (dnsxExec, ("permutated_subs_output.txt", "dnsx_permutated_resolved_output.txt", target_domain)),
    }
    runToolsParallel(tools2)

    anewExec(f"{target_domain}/domain-recon/dnsx_permutated_resolved_output.txt", f"{target_domain}/domain-recon/dnsx_all_resolved.txt")


def finalHttpxScan(target_domain):
    """Run final httpx scan on all resolved subdomains."""
    console.print("\n[bold green]HTTPX Scan[/bold green]\n")

    tools = {
        "httpx": (httpxExec, (target_domain, f"{target_domain}/domain-recon/dnsx_all_resolved.txt")),
    }
    runToolsParallel(tools)


def cleanup(target_domain):
    """Remove intermediate files."""
    directory = Path(f"{target_domain}/domain-recon/")
    for pattern in ["*_output.txt", "permutated_*", "dnsx_permutated_*", "all_subs.txt", "bbot_*"]:
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
