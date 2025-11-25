import subprocess

def dnsx_exec(subs_file, out_file_name, target):
    result = subprocess.run(
        [
            "dnsx",
            "-l",
            f"{subs_file}",
            "-o",
            f"{target}/domain-recon/{out_file_name}",
            "-silent",
            "-nc",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print(f"[!] dnsx resolve for {subs_file[len(target)+14:len(subs_file)-4]} complete")
    else:
        print(f"[!] dnsx failed with error: {result.stderr}")
    print("\n")

def shuffledns_exec(target, wordlist, out_file_name):
    resolvers = "/home/d0b0/.config/shuffledns/resolvers.txt"
    result = subprocess.run(
        [
            "shuffledns",
            "-d",
            f"{target}",
            "-w",
            f"{wordlist}",
            "-r",
            f"{resolvers}",
            "-mode",
            "bruteforce",
            "-o",
            f"{target}/domain-recon/{out_file_name}",
            "-silent",
            "-nc",
        ],
        stdout=subprocess.DEVNULL,
        capture_output=False
    )
    if result.returncode == 0:
        print(f"[!] shuffledns wordlist {wordlist[34:]} done")
    else:
        print(f"[!] shuffledns failed with error: {result.stderr}")
    print("\n")


def subfinder_exec(target_domain):
    result = subprocess.run(
        [
            "subfinder",
            "-d",
            f"{target_domain}",
            "-all",
            "-silent",
            "-o",
            f"{target_domain}/domain-recon/subfinder_output.txt",
        ],
        stdout=subprocess.DEVNULL,
    )

    if result.returncode == 0:
        print("[+] Subfinder done")
    else:
        print(f"[!] Subfinder failed with error: {result.stderr}")
    print("\n")


def httpx_exec(target_domain):
    print("[+] Starting HTTPX...")
    result = subprocess.run(
        [
            "httpx",
            "-silent",
            "-no-color",
            "-l",
            f"{target_domain}/domain-recon/resolved_subs.txt",
            "-fc",
            "404",
            "-sc",
            "-location",
            "-server",
            "-cdn",
            "-title",
            "-rl",
            "50",
            "-p",
            "80,443,8080,8000,8443",
            "-o",
            f"{target_domain}/domain-recon/httpx_full_scan.txt",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print("[+] HTTPX done!")
    else:
        print(f"[!] HTTPX failed with error: {result.stderr}")


def gotator_exec(target_domain):

    input_file = f"{target_domain}/domain-recon/all_subs.txt"
    output_file = f"{target_domain}/domain-recon/permutated_subs.txt"

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
    try:
        with open(input_file, "r") as f:
            result = subprocess.run(
                ["anew", target_file],
                stdin=f,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL  # Optional: suppress anew errors too
            )
        # If subprocess fails (e.g. 'anew' command not found), you can check result.returncode if needed
        if result.returncode != 0:
            print(f"[!] 'anew' command failed with return code {result.returncode}")
        
    except FileNotFoundError:
        print(f"[!] File not found: {input_file}")
        # Continue execution (no exception raised)
    
    except PermissionError:
        print(f"[!] Permission denied when accessing file: {input_file}")
    
    except Exception as e:
        print(f"[!] An unexpected error occurred: {type(e).__name__}: {e}")