import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from pathlib import Path
import json
import time
from src.output import info, error


def dnsxExec(subs_file, out_file_name, target):
    """Resolve subdomains with dnsx."""
    output_file = f"{target}/domain-recon/{out_file_name}"
    result = subprocess.run(
        ["dnsx", "-l", f"{target}/domain-recon/{subs_file}", "-o", output_file, "-silent", "-nc"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"dnsx failed: {result.stderr.decode()}")

def shufflednsExec(target, wordlist, out_file_name):
    """Run shuffledns DNS bruteforce."""
    resolvers = "/home/d0b0/.config/shuffledns/resolvers.txt"
    result = subprocess.run(
        ["shuffledns", "-d", target, "-w", wordlist, "-r", resolvers, "-mode", "bruteforce",
         "-o", f"{target}/domain-recon/{out_file_name}", "-silent", "-nc", "-t", "1000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"shuffledns failed: {result.stderr.decode()}")

def subfinderExec(target_domain):
    """Run subfinder subdomain discovery."""
    result = subprocess.run(
        ["subfinder", "-d", target_domain, "-all", "-silent", "-o", f"{target_domain}/domain-recon/subfinder_output.txt"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"subfinder failed: {result.stderr.decode()}")

def httpxExec(target_domain, subs_file):
    """Probe subdomains with httpx."""
    out_file_name = Path(subs_file).stem
    output_file = f"{target_domain}/domain-recon/httpx_{out_file_name}_scan.txt"
    result = subprocess.run(
        ["httpx", "-silent", "-l", subs_file, "-fc", "404", "-sc", "-location", "-server", "-cdn", "-title",
         "-rl", "50", "-p", "80,443,8080,8000,8443", "-o", output_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"httpx failed: {result.stderr.decode()}")

def alterxExec(target_domain):
    """Generate subdomain permutations with alterx."""
    result = subprocess.run(
        ["alterx", "-silent", "-enrich", "-l", f"{target_domain}/domain-recon/dnsx_all_resolved.txt",
         "-o", f"{target_domain}/domain-recon/permutated_subs_output.txt"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"alterx failed: {result.stderr.decode()}")

def bbotExec(target_domain):
    """Run bbot subdomain enumeration (passive only)."""
    result = subprocess.run(
        ["bbot", "-t", target_domain, "-p", "subdomain-enum",
         "-rf", "passive",
         "-n", target_domain, "-om", "subdomains",
         "-y", "-s"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        raise Exception(f"bbot failed: {result.stderr.decode()}")

def bbotExtractAndAppend(target_domain):
    """Extract DNS_NAME entries from bbot output and append to all_subs.txt."""
    bbot_output = Path.home() / f".bbot/scans/{target_domain}/output.txt"
    temp_dns_file = f"{target_domain}/domain-recon/bbot_dns_names.txt"
    
    if bbot_output.exists():
        # Extract DNS names
        result = subprocess.run(
            f"cat {bbot_output} | grep 'DNS_NAME' | awk '{{print $1}}' > {temp_dns_file}",
            shell=True, capture_output=True
        )
        if result.returncode == 0 and Path(temp_dns_file).exists():
            # Append to all_subs.txt using anew
            anewExec(temp_dns_file, f"{target_domain}/domain-recon/all_subs.txt")
            # Clean up temp file
            Path(temp_dns_file).unlink(missing_ok=True)
        else:
            error("Failed to extract BBOT results")
    else:
        error(f"BBOT output file not found: {bbot_output}")

def anewExec(input_file, target_file):
    try:
        Path(target_file).touch(exist_ok=True)
        with open(input_file) as f:
            result = subprocess.run(["anew", target_file], stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        if result.returncode != 0:
            error(f"'anew' failed with return code {result.returncode}")
    except FileNotFoundError:
        error(f"File not found: {input_file}")
    except PermissionError:
        error(f"Permission denied: {input_file}")
    except Exception as e:
        error(f"Error: {type(e).__name__}: {e}")

def crtshRequest(target_domain, max_retries=5):
    """Fetch subdomains from crt.sh API."""
    target_domain = target_domain.lstrip('.').lower()
    url = f"https://crt.sh/?q={target_domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"}
    
    for attempt in range(1, max_retries + 1):
        try:
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
            
            return
        
        except (HTTPError, URLError, json.JSONDecodeError) as e:
            if attempt < max_retries:
                time.sleep(2)
            else:
                raise
        except Exception as e:
            raise