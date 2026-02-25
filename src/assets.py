from pathlib import Path
from src.commands import *
from src.output import run_tools_parallel, error, console


def subdomain_enumeration(target_domain, first_wordlist, second_wordlist):
    """Passive and active gathering workflow using crtsh, subfinder, shuffledns, and bbot."""
    console.print("\n[bold green]Gathering Subdomains...[/bold green]\n")
    first_wordlist_name = Path(first_wordlist).stem
    second_wordlist_name = Path(second_wordlist).stem if second_wordlist else None

    tools = {
        "crt.sh": (crtsh_request, (target_domain,)),
        "subfinder": (subfinder_exec, (target_domain,)),
        "bbot": (bbot_exec, (target_domain,)),
        "shuffledns-1": (shuffledns_exec, (target_domain, first_wordlist, f"shuffledns_{first_wordlist_name}_output.txt")),
    }
    
    if second_wordlist:
        tools["shuffledns-2"] = (shuffledns_exec, (target_domain, second_wordlist, f"shuffledns_{second_wordlist_name}_output.txt"))
    
    run_tools_parallel(tools)

    bbot_extract_and_append(target_domain)

    source_files = ["subfinder_output.txt", "crtsh_output.txt", 
                    f"shuffledns_{first_wordlist_name}_output.txt"]
    if second_wordlist:
        source_files.append(f"shuffledns_{second_wordlist_name}_output.txt")
    
    for src in source_files:
        anew_exec(f"{target_domain}/domain-recon/{src}", f"{target_domain}/domain-recon/all_subs.txt")


def subdomain_resolve_permute(target_domain):
    """Resolve and permutate subdomains with dnsx and alterx."""
    console.print("\n[bold green]Resolving and Permutation[/bold green]\n")

    tools = {
        "dnsx": (dnsx_exec, ("all_subs.txt", "dnsx_all_resolved.txt", target_domain)),
    }
    run_tools_parallel(tools)

    tools1 = {
        "alterx": (alterx_exec, (target_domain,)),
    }
    run_tools_parallel(tools1)

    tools2 = {
        "dnsx-permutated": (dnsx_exec, ("permutated_subs_output.txt", "dnsx_permutated_resolved_output.txt", target_domain)),
    }
    run_tools_parallel(tools2)

    anew_exec(f"{target_domain}/domain-recon/dnsx_permutated_resolved_output.txt", f"{target_domain}/domain-recon/dnsx_all_resolved.txt")


def final_httpx_scan(target_domain):
    """Run final httpx scan on all resolved subdomains."""
    console.print("\n[bold green]HTTPX Scan[/bold green]\n")

    tools = {
        "httpx": (httpx_exec, (target_domain, f"{target_domain}/domain-recon/dnsx_all_resolved.txt")),
    }
    run_tools_parallel(tools)


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
    
    bbot_scan_dir = Path.home() / f".bbot/scans/{target_domain}"
    if bbot_scan_dir.exists():
        import shutil
        try:
            shutil.rmtree(bbot_scan_dir)
        except Exception as e:
            error(f"Error deleting BBOT scan directory: {e}")
