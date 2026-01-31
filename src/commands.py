import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from pathlib import Path
import socket
import json
import time

def dnsx_exec(subs_file, out_file_name, target):
    print(f"[+] Started resolving {subs_file}.")
    result = subprocess.run(
        [
            "dnsx",
            "-l",
            f"{target}/domain-recon/{subs_file}",
            "-o",
            f"{target}/domain-recon/{out_file_name}",
            "-silent",
            "-nc",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print(f"[!] Resolving of {subs_file} complete.")
    else:
        print(f"[!] dnsx failed with error: {result.stderr}.")

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
            "-t",
            "1000"
        ],
        stdout=subprocess.DEVNULL,
        capture_output=False
    )
    if result.returncode == 0:
        print(f"[!] shuffledns wordlist {wordlist} done")
    else:
        print(f"[!] shuffledns failed with error: {result.stderr}")

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
        print("[!] Subfinder done")
    else:
        print(f"[!] Subfinder failed with error: {result.stderr}")

def httpx_exec(target_domain, subs_file):
    print("[+] Starting HTTPX...")
    out_file_name=Path(subs_file).stem
    result = subprocess.run(
        [
            "httpx",
            "-silent",
            "-l",
            subs_file,
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
            f"{target_domain}/domain-recon/httpx_{out_file_name}_scan.txt",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print("[!] HTTPX done!")
    else:
        print(f"[!] HTTPX failed with error: {result.stderr}")

def alterx_exec(target_domain):
    print("[+] Starting AlterX...")

    input_file = f"{target_domain}/domain-recon/resolved_subs.txt"
    output_file = f"{target_domain}/domain-recon/permutated_subs.txt"
    result = subprocess.run(
        [
            "alterx",
            "-silent",
            "-enrich",
            "-l",
            f"{input_file}",
            "-o",
            f"{output_file}",
        ],
        stdout=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        print("[!] AlterX done!")
    else:
        print(f"[!] AlterX failed with error: {result.stderr}")

def anew_exec(input_file, target_file):
    try:
        with open(input_file, "r") as f:
            result = subprocess.run(
                ["anew", target_file],
                stdin=f,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT
            )
        # If subprocess fails (e.g. 'anew' command not found), check result.returncode
        if result.returncode != 0:
            print(f"[!] 'anew' command failed with return code {result.returncode}")
        
    except FileNotFoundError:
        print(f"[!] File not found: {input_file}")
        # Continue execution (no exception raised)
    
    except PermissionError:
        print(f"[!] Permission denied when accessing file: {input_file}")
    
    except Exception as e:
        print(f"[!] An unexpected error occurred: {type(e).__name__}: {e}")

def crtsh_request(target_domain, max_retries=5):
    print("[+] Fetching data from crt.sh...")
    target_domain = target_domain.lstrip('.').lower()
    url = f"https://crt.sh/?q={target_domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
    }
    
    for attempt in range(1, max_retries + 1):
        try:
            if attempt > 1:
                print(f"[*] Retry attempt {attempt}/{max_retries}...")
            
            req = Request(url, headers=headers)
            with urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
            
            print("[+] crt.sh request successful")
            json_response = json.loads(data)
            subdomains = set()
            
            for item in json_response:
                for name in item.get("name_value", "").splitlines():
                    name = name.strip().lower()
                    if not name:
                        continue
                    if name.endswith(f".{target_domain}") or name == target_domain:
                        # Remove leading "*." if present (for both *.sub.domain.com and *.domain.com)
                        if name.startswith("*."):
                            cleaned = name[2:]  # removes "*."
                        else:
                            cleaned = name
                        subdomains.add(cleaned)
            
            output_file = f"{target_domain}/domain-recon/crtsh_output.txt"
            with open(output_file, "w", encoding="utf-8") as f:
                for subdomain in sorted(subdomains):
                    f.write(subdomain + "\n")
            
            print(f"[+] Found {len(subdomains)} unique subdomains on crt.sh")
            return  # Success - exit the function
        
        except socket.timeout:
            print(f"[!] Timeout on crt.sh after 30s (attempt {attempt}/{max_retries})")
        except HTTPError as e:
            print(f"[!] HTTP {e.code} - {e.reason} (attempt {attempt}/{max_retries})")
        except URLError as e:
            print(f"[!] Network error: {e.reason} (attempt {attempt}/{max_retries})")
        except json.JSONDecodeError:
            print(f"[!] Invalid JSON received (attempt {attempt}/{max_retries})")
        except Exception as e:
            print(f"[!] Unexpected error: {e} (attempt {attempt}/{max_retries})")
        
        # If this wasn't the last attempt, wait a bit before retrying
        if attempt < max_retries:
            time.sleep(2)  # Wait 2 seconds between retries
    
    print(f"[!] Failed to fetch data from crt.sh after {max_retries} attempts")