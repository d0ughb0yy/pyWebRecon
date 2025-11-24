import subprocess
from pathlib import Path

def dnsx_exec(target, wordlist, out_file_name):
    result = subprocess.run(
        [
            "dnsx",
            "-d",
            f"{target}",
            "-w",
            f"{wordlist}",
            "-o",
            f"{target}/domain-recon/{out_file_name}",
            "-silent",
            "-nc",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print(f"[!] dnsx wordlist {wordlist[34:]} done")
    else:
        print(f"[!] dnsx failed with error: {result.stderr}")
    print("\n")


def subfinder_exec(target_domain, recon_dir):
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
        print("[+] Subfinder done")
    else:
        print(f"[!] Subfinder failed with error: {result.stderr}")
    print("\n")


def httpx_exec(recon_dir):
    print("[+] Starting HTTPX...")
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

def gotator_exec(recon_dir):
    
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

def anew_exec(input_file, target_file):
    with open(input_file, "r") as f:
        result = subprocess.run(
            ["anew", target_file], stdin=f, stdout=subprocess.DEVNULL
        )
    if result.returncode != 0:
        print(f"Error: {result.stderr}")