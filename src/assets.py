import threading
from pathlib import Path
import os
from src.commands import *


def subdomain_enumeration(target_domain, first_wordlist, second_wordlist):
    """Uses subfinder, shuffledns, and crt.sh data to enumerate subdomains for a given target"""

    # Fetch subdomains from crt.sh
    crtsh_request(target_domain)

    # Start the subfinder thread
    subfinder_thread = threading.Thread(
        target=subfinder_exec, args=[target_domain], name="subfinder thread"
    )
    print(f"[+] Starting {subfinder_thread.name}")
    subfinder_thread.start()

    # Fetch wordlist names
    first_wordlist_name=Path(first_wordlist).stem
    second_wordlist_name=Path(second_wordlist).stem

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
    print(f"[+] Starting {first_shuffledns_thread.name}")
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
    print(f"[+] Starting {second_shuffledns_thread.name}")
    second_shuffledns_thread.start()

    # Make sure that the program does not progress until
    # all threads are complete
    first_shuffledns_thread.join()
    second_shuffledns_thread.join()
    subfinder_thread.join()

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
        f"{target_domain}/domain-recon/shuffledns_{first_wordlist[34 : len(first_wordlist) - 4]}_output.txt",
        f"{target_domain}/domain-recon/all_subs.txt",
    )
    anew_exec(
        f"{target_domain}/domain-recon/shuffledns_{second_wordlist[34 : len(second_wordlist) - 4]}_output.txt",
        f"{target_domain}/domain-recon/all_subs.txt",
    )


def subdomain_resolve(target_domain):
    """Takes a target domain and resolves all gathered subdomains of the target"""

    # Start resolving normal subdomains
    dnsx_normal_thread = threading.Thread(
        target=dnsx_exec,
        args=(
            f"{target_domain}/domain-recon/all_subs.txt",
            "dnsx_resolved.txt",
            target_domain,
        ),
        name="dnsx normal thread",
    )
    print(f"Starting {dnsx_normal_thread.name}...")
    dnsx_normal_thread.start()

    # Start resolving permutated domains
    dnsx_permutated_thread = threading.Thread(
        target=dnsx_exec,
        args=(
            f"{target_domain}/domain-recon/permutated_subs.txt",
            "dnsx_permutated_resolved.txt",
            target_domain,
        ),
        name="dnsx permutated thread",
    )
    print(f"Starting {dnsx_permutated_thread.name}...")
    dnsx_permutated_thread.start()

    dnsx_normal_thread.join()
    dnsx_permutated_thread.join()

    # Add those that resolve to the group file
    anew_exec(
        f"{target_domain}/domain-recon/dnsx_resolved.txt",
        f"{target_domain}/domain-recon/resolved_subs.txt",
    )
    anew_exec(
        f"{target_domain}/domain-recon/dnsx_permutated_resolved.txt",
        f"{target_domain}/domain-recon/resolved_subs.txt",
    )

def delete_specified(name, target_domain):
    # Specify the directory (current directory by default)
    directory = Path(
        target_domain + "/domain-recon/"
    )

    # Remove files using wildcard notation *_output.txt, subfinder_*, etc
    for file_path in directory.glob(name):
        if file_path.is_file():  # extra safety
            try:
                file_path.unlink()
                print(f"Deleted: {file_path}")
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")


def cleanup(target_domain):
    delete_specified("*_output.txt", target_domain)
    delete_specified("*_resolved.txt", target_domain)
    os.remove(f"{target_domain}/domain-recon/permutated_subs.txt")
