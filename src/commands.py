import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from pathlib import Path
import json
import time

def run_tool(cmd, success_msg, error_msg):
    """Helper to run subprocess commands with consistent error handling."""
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    print(success_msg if result.returncode == 0 else f"[!] {error_msg}: {result.stderr.decode()}")
    return result.returncode == 0

def dnsx_exec(subs_file, out_file_name, target):
    print(f"[+] Started resolving {subs_file}.")
    run_tool(
        ["dnsx", "-l", f"{target}/domain-recon/{subs_file}", "-o", f"{target}/domain-recon/{out_file_name}", "-silent", "-nc"],
        f"[!] Resolving of {subs_file} complete.",
        "dnsx failed"
    )

def shuffledns_exec(target, wordlist, out_file_name):
    resolvers = "/home/d0b0/.config/shuffledns/resolvers.txt"
    run_tool(
        ["shuffledns", "-d", target, "-w", wordlist, "-r", resolvers, "-mode", "bruteforce",
         "-o", f"{target}/domain-recon/{out_file_name}", "-silent", "-nc", "-t", "1000"],
        f"[!] shuffledns wordlist {Path(wordlist).stem} done",
        "shuffledns failed"
    )

def subfinder_exec(target_domain):
    run_tool(
        ["subfinder", "-d", target_domain, "-all", "-silent", "-o", f"{target_domain}/domain-recon/subfinder_output.txt"],
        "[!] Subfinder done",
        "Subfinder failed"
    )

def httpx_exec(target_domain, subs_file):
    print("[+] Starting HTTPX...")
    out_file_name = Path(subs_file).stem
    run_tool(
        ["httpx", "-silent", "-l", subs_file, "-fc", "404", "-sc", "-location", "-server", "-cdn", "-title",
         "-rl", "50", "-p", "80,443,8080,8000,8443", "-o", f"{target_domain}/domain-recon/httpx_{out_file_name}_scan.txt"],
        "[!] HTTPX done!",
        "HTTPX failed"
    )

def alterx_exec(target_domain):
    print("[+] Starting AlterX...")
    run_tool(
        ["alterx", "-silent", "-enrich", "-l", f"{target_domain}/domain-recon/dnsx_all_resolved.txt",
         "-o", f"{target_domain}/domain-recon/permutated_subs_output.txt"],
        "[!] AlterX done!",
        "AlterX failed"
    )

def anew_exec(input_file, target_file):
    try:
        with open(input_file) as f:
            result = subprocess.run(["anew", target_file], stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if result.returncode != 0:
            print(f"[!] 'anew' failed with return code {result.returncode}")
    except FileNotFoundError:
        print(f"[!] File not found: {input_file}")
    except PermissionError:
        print(f"[!] Permission denied: {input_file}")
    except Exception as e:
        print(f"[!] Error: {type(e).__name__}: {e}")

def crtsh_request(target_domain, max_retries=5):
    print("[+] Fetching data from crt.sh...")
    target_domain = target_domain.lstrip('.').lower()
    url = f"https://crt.sh/?q={target_domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"}
    
    for attempt in range(1, max_retries + 1):
        try:
            if attempt > 1:
                print(f"[*] Retry attempt {attempt}/{max_retries}...")
            
            req = Request(url, headers=headers)
            with urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
            
            subdomains = set()
            for item in data:
                for name in item.get("name_value", "").splitlines():
                    name = name.strip().lower()
                    if name and (name.endswith(f".{target_domain}") or name == target_domain):
                        subdomains.add(name[2:] if name.startswith("*.") else name)
            
            with open(f"{target_domain}/domain-recon/crtsh_output.txt", "w") as f:
                f.write("\n".join(sorted(subdomains)))
            
            print(f"[+] Found {len(subdomains)} unique subdomains on crt.sh")
            return
        
        except HTTPError as e:
            print(f"[!] HTTP {e.code} - {e.reason} (attempt {attempt}/{max_retries})")
        except URLError as e:
            print(f"[!] Network error: {e.reason} (attempt {attempt}/{max_retries})")
        except json.JSONDecodeError:
            print(f"[!] Invalid JSON received (attempt {attempt}/{max_retries})")
        except Exception as e:
            print(f"[!] Error: {e} (attempt {attempt}/{max_retries})")
        
        if attempt < max_retries:
            time.sleep(2)
    
    print(f"[!] Failed to fetch data from crt.sh after {max_retries} attempts")