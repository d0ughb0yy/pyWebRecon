import threading
import time
from pathlib import Path
from src.commands import *
from src.output import run_tools_with_live_table, success, error, console


def subdomain_enumeration(target_domain, first_wordlist, second_wordlist):
    """Passive and active gathering workflow using crtsh, subfinder, shuffledns, and bbot."""
    console.print("\n[bold green]Subdomain Enumeration[/bold green]")
    console.print("-" * 50)
    first_wordlist_name = Path(first_wordlist).stem
    second_wordlist_name = Path(second_wordlist).stem

    # Define all tools for enumeration phase
    tools = {
        "crt.sh": (crtsh_request, (target_domain,)),
        "subfinder": (subfinder_exec, (target_domain,)),
        "bbot": (bbot_exec, (target_domain,)),
        "shuffledns-1": (shuffledns_exec, (target_domain, first_wordlist, f"shuffledns_{first_wordlist_name}_output.txt")),
        "shuffledns-2": (shuffledns_exec, (target_domain, second_wordlist, f"shuffledns_{second_wordlist_name}_output.txt")),
    }
    
    # Run all tools with live status table
    run_tools_with_live_table(tools)

    # Process BBOT results after all threads complete
    bbot_extract_and_append(target_domain)

    # Combine all results into all_subs.txt
    for src in ["subfinder_output.txt", "crtsh_output.txt", 
                f"shuffledns_{first_wordlist_name}_output.txt", 
                f"shuffledns_{second_wordlist_name}_output.txt"]:
        anew_exec(f"{target_domain}/domain-recon/{src}", f"{target_domain}/domain-recon/all_subs.txt")


def subdomain_resolve(target_domain):
    """Resolve subdomains with dnsx."""
    console.print("\n[bold green]Resolving Subdomains[/bold green]")
    console.print("-" * 50)

    tools = {
        "dnsx": (dnsx_exec, ("all_subs.txt", "dnsx_all_resolved.txt", target_domain)),
    }
    run_tools_with_live_table(tools)


def subdomain_permutation(target_domain):
    """Permutate and resolve subdomains with alterx."""
    console.print("\n[bold green]Permutating Subdomains[/bold green]")
    console.print("-" * 50)

    tools1 = {
        "alterx": (alterx_exec, (target_domain,)),
    }
    run_tools_with_live_table(tools1)

    tools2 = {
        "dnsx-permutated": (dnsx_exec, ("permutated_subs_output.txt", "dnsx_permutated_resolved_output.txt", target_domain)),
    }
    run_tools_with_live_table(tools2)

    anew_exec(f"{target_domain}/domain-recon/dnsx_permutated_resolved_output.txt", f"{target_domain}/domain-recon/dnsx_all_resolved.txt")


def final_httpx_scan(target_domain):
    """Run final httpx scan on all resolved subdomains."""
    console.print("\n[bold green]HTTPX Scan[/bold green]")
    console.print("-" * 50)

    tools = {
        "httpx": (httpx_exec, (target_domain, f"{target_domain}/domain-recon/dnsx_all_resolved.txt")),
    }
    run_tools_with_live_table(tools)


def cleanup(target_domain):
    """Remove intermediate files."""
    directory = Path(f"{target_domain}/domain-recon/")
    for pattern in ["*_output.txt", "permutated_*", "dnsx_permutated_*", "all_subs.txt", "bbot_*"]:
        for file_path in directory.glob(pattern):
            if file_path.is_file():
                try:
                    file_path.unlink()
                    success(f"Deleted: {file_path}")
                except Exception as e:
                    error(f"Error deleting {file_path}: {e}")
    
    # Clean up BBOT scan directory
    bbot_scan_dir = Path.home() / f".bbot/scans/{target_domain}"
    if bbot_scan_dir.exists():
        import shutil
        try:
            shutil.rmtree(bbot_scan_dir)
            success(f"Deleted BBOT scan directory: {bbot_scan_dir}")
        except Exception as e:
            error(f"Error deleting BBOT scan directory: {e}")
