import threading
from pathlib import Path
from src.commands import *


def subdomain_enumeration(target_domain, first_wordlist, second_wordlist):
    """Passive and active gathering workflow using crtsh, subfinder and shuffledns."""
    first_wordlist_name = Path(first_wordlist).stem
    second_wordlist_name = Path(second_wordlist).stem

    crtsh_request(target_domain)

    threads = [
        threading.Thread(target=subfinder_exec, args=[target_domain], name="subfinder"),
        threading.Thread(target=shuffledns_exec, args=(target_domain, first_wordlist, f"shuffledns_{first_wordlist_name}_output.txt"), name="shuffledns-1"),
        threading.Thread(target=shuffledns_exec, args=(target_domain, second_wordlist, f"shuffledns_{second_wordlist_name}_output.txt"), name="shuffledns-2"),
    ]

    for t in threads:
        print(f"[+] Starting {t.name}.")
        t.start()
    for t in threads:
        t.join()

    # Combine all results into all_subs.txt
    for src in ["subfinder_output.txt", "crtsh_output.txt", 
                f"shuffledns_{first_wordlist_name}_output.txt", 
                f"shuffledns_{second_wordlist_name}_output.txt"]:
        anew_exec(f"{target_domain}/domain-recon/{src}", f"{target_domain}/domain-recon/all_subs.txt")


def subdomain_resolve(target_domain):
    """Resolve subdomains with dnsx and probe with httpx."""
    dnsx_exec("all_subs.txt", "dnsx_all_resolved.txt", target_domain)
    httpx_exec(target_domain, f"{target_domain}/domain-recon/dnsx_all_resolved.txt")


def subdomain_permutation(target_domain):
    """Permutate and resolve subdomains with alterx."""
    alterx_exec(target_domain)
    dnsx_exec("permutated_subs_output.txt", "dnsx_permutated_resolved_output.txt", target_domain)
    httpx_exec(target_domain, f"{target_domain}/domain-recon/dnsx_permutated_resolved_output.txt")
    
    for src, dst in [("dnsx_permutated_resolved_output.txt", "dnsx_all_resolved.txt"),
                     ("httpx_dnsx_permutated_resolved_output_scan.txt", "httpx_all_subs_scan.txt")]:
        anew_exec(f"{target_domain}/domain-recon/{src}", f"{target_domain}/domain-recon/{dst}")


def cleanup(target_domain):
    """Remove intermediate files."""
    directory = Path(f"{target_domain}/domain-recon/")
    for pattern in ["*_output.txt", "*_permutated_*", "all_subs.txt", "httpx_dnsx_*_scan.txt"]:
        for file_path in directory.glob(pattern):
            if file_path.is_file():
                try:
                    file_path.unlink()
                    print(f"[+] Deleted: {file_path}")
                except Exception as e:
                    print(f"[!] Error deleting {file_path}: {e}")
