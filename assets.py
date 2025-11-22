import subprocess
from pathlib import Path
import threading


def append_subfinder_files(input_file, target_file):
    with open(input_file, "r") as f:
        result = subprocess.run(
            ["anew", target_file], stdin=f, stdout=subprocess.DEVNULL
        )
    if result.returncode != 0:
        print(f"Error: {result.stderr}")


def append_gobuster_files(gobuster_file: str, all_subs_file: str):
    gobuster_path = Path(gobuster_file)
    all_subs_path = Path(all_subs_file)

    if not gobuster_path.exists():
        print(f"[!] Gobuster file not found: {gobuster_file}")
        return

    existing = set()
    if all_subs_path.exists():
        with open(all_subs_path, "r", encoding="utf-8") as f:
            existing = {line.strip() for line in f if line.strip()}

    new_domains = []
    with open(gobuster_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Handle both formats
            # sub.domain.com 1.2.3.4
            # Found: sub.domain.dom 1.2.3.4
            if " " in line:
                domain = line.split()[0]
            elif line.startswith("Found:"):
                domain = line.split("Found:")[1].strip().split()[0]
            else:
                domain = line

            domain = domain.lower().split("[")[0].rstrip(":").strip()

            if domain and domain not in existing:
                new_domains.append(domain)
                existing.add(domain)

        if new_domains:
            with open(all_subs_path, "a", encoding="utf-8") as f:
                for domain in new_domains:
                    f.write(domain + "\n")
            print(f"[+] Added {len(new_domains)} new domains from gobuster")
        else:
            print("[*] No new subdomains found in gobuster files")


def gobuster_exec(target, wordlist, out_file_name):

    result = subprocess.run(
        [
            "gobuster",
            "dns",
            "--do",
            f"{target}",
            "-w",
            f"{wordlist}",
            "--no-error",
            "--no-color",
            "--no-progress",
            "--wildcard",
            "-o",
            f"{target}/domain-recon/{out_file_name}",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print("[+] Gobuster done!")
    else:
        print(f"[!] Gobuster failed with error: {result.stderr}")
    print("\n")


def subdomain_enumeration(target_domain, recon_dir, first_wordlist, second_wordlist):
    """Uses Subfinder and Puredns CLI tools to enumerate subdomains for a given target"""

    # BEGIN SUBFINDER PROCESS
    print(
        "========================= Beginning Subfinder Enumeration ======================="
    )

    # Executes subfinder with the give target domain and uses shlex to separate the output
    result = subprocess.run(
        [
            "subfinder",
            "-d",
            f"{target_domain}",
            "-all",
            "-silent",
            "-o",
            f"{recon_dir}/domain-recon/subfinder_output.txt",
        ],
        stdout=subprocess.DEVNULL,
    )

    if result.returncode == 0:
        print("[+] Subfinder done!")
    else:
        print(f"[!] Subfinder failed with error: {result.stderr}")
    print("\n")
    # END SUBFINDER PROCESS

    # BRUTEFORCE SUBDOMAINS
    print(
        "======================= Beginning Bruteforcing Subdomains ======================="
    )

    first_thread = threading.Thread(
        target=gobuster_exec,
        args=(
            target_domain,
            first_wordlist,
            first_wordlist[34 : len(first_wordlist) - 4],
        ),
    )
    first_thread.start()

    second_thread = threading.Thread(
        target=gobuster_exec,
        args=(
            target_domain,
            second_wordlist,
            f"gobuster_{second_wordlist[34:len(second_wordlist)-4]}_output.txt",
        ),
    )
    second_thread.start()

    first_thread.join()
    second_thread.join()

    # END BRUTEFORCE PROCESS

    # ANEW SUBDOMAIN FILES
    append_subfinder_files(
        f"{recon_dir}/domain-recon/subfinder_output.txt",
        f"{recon_dir}/domain-recon/all_subs.txt",
    )

    append_gobuster_files(
        f"{recon_dir}/domain-recon/gobuster_dns_output.txt",
        f"{recon_dir}/domain-recon/all_subs.txt",
    )


def subdomain_permutation(recon_dir):
    """Uses gotator to permutate subdomains"""

    print(
        "======================== Beginning Subdomain Permutation ========================"
    )

    input_file = f"{recon_dir}/domain-recon/all_subs.txt"
    output_file = f"{recon_dir}/domain-recon/permutated_subs.txt"

    with open(output_file, "w") as outfile:
        result = subprocess.run(
            ["gotator", "-sub", input_file, "-md", "-silent"],
            stdout=outfile,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    if result.returncode == 0:
        print(f"[+] Gotator completed!")
    else:
        print(f"[!] Gotator failed with error {result.stderr}")
    print("\n")


def probe(recon_dir):
    """Uses httpx to probe for live hosts"""
    print(
        "============================ Beginning httpx Probing ============================"
    )

    result = subprocess.run(
        [
            "httpx",
            "-silent",
            "-l",
            f"{recon_dir}/all_subs.txt",
            "-fc",
            "404",
            "-sc",
            "-location",
            "-server",
            "-cdn",
            "-title",
            "-rl",
            "50",
            "-no-color",
            "-o",
            f"{recon_dir}/httpx_full_scan.txt",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print("[+] HTTPX done!")
    else:
        print(f"[!] HTTPX failed with error: {result.stderr}")
