import threading
from pathlib import Path
from urllib.request import urlopen
import json
import os
from src.commands import *


def crtsh_request(target_domain):
    print("[+] Fetching data from crt.sh...")
    response = urlopen(f"https://crt.sh/?q={target_domain}&output=json")

    if TimeoutError:
        print("[!] Timeout on crt.sh")
        pass
    else:
        print("[+] crt.sh request successful")

        json_response = json.loads(response.read())

        raw_output = []

        for item in json_response:
            for name in item.get("name_value", "").splitlines():
                name = name.strip()

                if not name:
                    continue

                if name.endswith(f".{target_domain}") or name == target_domain:
                    # Remove leading "*." if present (for both *.sub.domain.com and *.domain.com)
                    if name.startswith("*."):
                        cleaned = name[2:]  # removes "*."
                    else:
                        cleaned = name
                    raw_output.append(cleaned)

        target_subdomains = set(raw_output)

        with open(f"{target_domain}/domain-recon/crtsh_output.txt", "a") as f:
            for item in target_subdomains:
                f.write(item + "\n")
            f.close()


def subdomain_enumeration(target_domain, first_wordlist, second_wordlist):
    """Uses Subfinder and Puredns CLI tools to enumerate subdomains for a given target"""

    crtsh_request(target_domain)

    subfinder_thread = threading.Thread(
        target=subfinder_exec, args=[target_domain], name="subfinder thread"
    )
    print(f"[+] Starting {subfinder_thread.name}")
    subfinder_thread.start()

    first_shuffledns_thread = threading.Thread(
        target=shuffledns_exec,
        args=(
            target_domain,
            first_wordlist,
            f"shuffledns_{first_wordlist[34 : len(first_wordlist) - 4]}_output.txt",
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
            f"shuffledns_{second_wordlist[34:len(second_wordlist)-4]}_output.txt",
        ),
        name="second shuffledns wordlist",
    )
    print(f"[+] Starting {second_shuffledns_thread.name}")
    second_shuffledns_thread.start()

    first_shuffledns_thread.join()
    second_shuffledns_thread.join()
    subfinder_thread.join()

    anew_exec(
        f"{target_domain}/domain-recon/subfinder_output.txt",
        f"{target_domain}/domain-recon/all_subs.txt",
    )

    anew_exec(  # Actually crtsh output but same file format
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


def subdomain_permutation(target_domain):
    """Uses gotator to permutate subdomains"""
    gotator_exec(target_domain)


def subdomain_resolve(target_domain):
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

    anew_exec(
        f"{target_domain}/domain-recon/dnsx_resolved.txt",
        f"{target_domain}/domain-recon/resolved_subs.txt",
    )
    anew_exec(
        f"{target_domain}/domain-recon/dnsx_permutated_resolved.txt",
        f"{target_domain}/domain-recon/resolved_subs.txt",
    )


def probe(target_domain):
    """Uses httpx to probe for live hosts"""
    httpx_exec(target_domain)


def delete_specified(name, target_domain):
    # Specify the directory (current directory by default)
    directory = Path(
        target_domain + "/domain-recon/"
    )  # or Path("/path/to/your/folder")

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
