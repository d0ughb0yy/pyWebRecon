import threading
from urllib.request import urlopen
import json
from commands import *

def crtsh_request(target_domain):
    print("[+] Fetching data from crt.sh...")
    response = urlopen(f"https://crt.sh/?q={target_domain}&output=json", timeout=20)

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
                    cleaned = name[2:] # removes "*."
                else:
                    cleaned = name
                raw_output.append(cleaned)
    
    target_subdomains = set(raw_output)
    return target_subdomains

def subdomain_enumeration(target_domain, recon_dir, first_wordlist, second_wordlist):
    """Uses Subfinder and Puredns CLI tools to enumerate subdomains for a given target"""

    crtsh_output = crtsh_request(target_domain)

    with open(f"{recon_dir}/domain-recon/crtsh_output.txt", "a") as f:
        for item in crtsh_output:
            f.write(item + '\n')
        f.close()
    print("[+] crt.sh request successful")

    subfinder_thread = threading.Thread(
        target=subfinder_exec,
        args=(target_domain, recon_dir),
        name="subfinder thread"
    )
    print(f"[+] Starting {subfinder_thread.name}")
    subfinder_thread.start()

    first_dnsx_thread = threading.Thread(
        target=dnsx_exec,
        args=(
            target_domain,
            first_wordlist,
            f"dnsx_{first_wordlist[34 : len(first_wordlist) - 4]}_output.txt",
        ),
        name="first dnsx wordlist"
    )
    print(f"[+] Starting {first_dnsx_thread.name}")
    first_dnsx_thread.start()

    second_dnsx_thread = threading.Thread(
        target=dnsx_exec,
        args=(
            target_domain,
            second_wordlist,
            f"dnsx_{second_wordlist[34:len(second_wordlist)-4]}_output.txt",
        ),
        name="second dnsx wordlist"
    )
    print(f"[+] Starting {second_dnsx_thread.name}")
    second_dnsx_thread.start()

    first_dnsx_thread.join()
    second_dnsx_thread.join()
    subfinder_thread.join()

    append_subfinder_output(
        f"{recon_dir}/domain-recon/subfinder_output.txt",
        f"{recon_dir}/domain-recon/all_subs.txt",
    )

    append_gobuster_output(
        f"{recon_dir}/domain-recon/gobuster_{first_wordlist[34 : len(first_wordlist) - 4]}_output.txt",
        f"{recon_dir}/domain-recon/all_subs.txt",
    )

    append_gobuster_output(
        f"gobuster_{second_wordlist[34:len(second_wordlist)-4]}_output.txt",
        f"{recon_dir}/domain-recon/all_subs.txt",
    )
    
    append_subfinder_output( # Actually crtsh output but same file format
        f"{recon_dir}/domain-recon/crtsh_output.txt",
        f"{recon_dir}/domain-recon/all_subs.txt",
    )


def subdomain_permutation(recon_dir):
    """Uses gotator to permutate subdomains"""
    gotator_exec(recon_dir)



def probe(recon_dir):
    """Uses httpx to probe for live hosts"""
    httpx_exec(recon_dir)


