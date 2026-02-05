import threading
from pathlib import Path
import os
from src.commands import *


def subdomain_enumeration(target_domain, first_wordlist, second_wordlist):
    """
    Passive and active gathering workflow,
    uses crtsh_request, subfinder_exec and shuffledns_exec,
    in the end it uses anew_exec to gather all data into a single file. 
    """

    # Fetch wordlist names
    first_wordlist_name = Path(first_wordlist).stem
    second_wordlist_name = Path(second_wordlist).stem

    # Fetch subdomains from crt.sh
    crtsh_request(target_domain)

    # Start the subfinder thread
    subfinder_thread = threading.Thread(
        target=subfinder_exec, args=[target_domain], name="subfinder thread"
    )
    print(f"[+] Starting {subfinder_thread.name}.")
    subfinder_thread.start()

    # Start shuffledns threads
    first_shuffledns_thread = threading.Thread(
        target=shuffledns_exec,
        args=(
            target_domain,
            first_wordlist,
            f"shuffledns_{first_wordlist_name}_output.txt",
        ),
        name="first shuffledns wordlist",
    )
    print(f"[+] Starting {first_shuffledns_thread.name}.")
    first_shuffledns_thread.start()

    second_shuffledns_thread = threading.Thread(
        target=shuffledns_exec,
        args=(
            target_domain,
            second_wordlist,
            f"shuffledns_{second_wordlist_name}_output.txt",
        ),
        name="second shuffledns wordlist",
    )
    print(f"[+] Starting {second_shuffledns_thread.name}.")
    second_shuffledns_thread.start()

    # Wait for all threads to finish
    subfinder_thread.join()
    first_shuffledns_thread.join()
    second_shuffledns_thread.join()

    # Use anew to build a text file for all gathered subdomains
    anew_exec(
        f"{target_domain}/domain-recon/subfinder_output.txt",
        f"{target_domain}/domain-recon/all_subs.txt",
    )

    anew_exec(
        f"{target_domain}/domain-recon/crtsh_output.txt",
        f"{target_domain}/domain-recon/all_subs.txt",
    )

    # Anew shuffledns files
    anew_exec(
        f"{target_domain}/domain-recon/shuffledns_{first_wordlist_name}_output.txt",
        f"{target_domain}/domain-recon/all_subs.txt",
    )
    anew_exec(
        f"{target_domain}/domain-recon/shuffledns_{second_wordlist_name}_output.txt",
        f"{target_domain}/domain-recon/all_subs.txt",
    )


def subdomain_resolve(target_domain):
    """
    Uses dnsx_exec to try and resolve all gathered subdomains
    and httpx to probe resolved hosts
    """

    subdomains_file = "all_subs.txt"
    out_file = "dnsx_all_resolved.txt"

    # Start resolving gathered subdomains
    dnsx_exec(subdomains_file, out_file, target_domain)

    # Use httpx to probe and scan the resolved subdomains
    httpx_exec(target_domain, f"{target_domain}/domain-recon/{out_file}")
    anew_exec(
        f"{target_domain}/domain-recon/httpx_{out_file}_scan.txt",
        f"{target_domain}/domain-recon/httpx_all_scan.txt"
    )


def subdomain_permutation(target_domain):
    """
    Uses alterx_exec and dnsx_exec to permutate and resolve.
    """
    permutated_subs_file = "permutated_subs.txt"
    dnsx_out_file = "dnsx_permutated_resolved.txt"

    # Execute AlterX
    alterx_exec(target_domain)

    # Start resolving permutated domains
    dnsx_exec(permutated_subs_file, dnsx_out_file, target_domain)

    httpx_exec(target_domain, f"{target_domain}/domain-recon/{dnsx_out_file}")

    anew_exec(
        f"{target_domain}/domain-recon/{dnsx_out_file}",
        f"{target_domain}/domain-recon/dnsx_all_resolved.txt"
    )

    anew_exec(
        f"{target_domain}/domain-recon/httpx_{Path(dnsx_out_file).stem}_scan.txt",
        f"{target_domain}/domain-recon/httpx_all_resolved_scan.txt",
    )


def delete_specified(name, target_domain):
    # Specify the directory (current directory by default)
    directory = Path(target_domain + "/domain-recon/")

    # Remove files using wildcard notation *_output.txt, subfinder_*, etc
    for file_path in directory.glob(name):
        if file_path.is_file():  # extra safety
            try:
                file_path.unlink()
                print(f"[+] Deleted: {file_path}")
            except Exception as e:
                print(f"[!] Error deleting {file_path}: {e}")


def cleanup(target_domain):
    delete_specified("*_output.txt", target_domain)
    delete_specified("*_permutated_*", target_domain)
    os.remove(f"{target_domain}/domain-recon/permutated_subs.txt")
