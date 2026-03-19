import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from pathlib import Path
import json
import time
import tempfile
import uuid
from src.output import error


def dnsxExec(domains, target_domain, output_filename):
    """Resolve subdomains with dnsx and return resolved domains as a set.
    
    Uses temporary files for input and output, then writes final results to the
    specified output filename in the target directory.
    """
    output_file = f"{target_domain}/domain-recon/{output_filename}"
    
    # Create temporary input file
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=True) as input_tmp:
        # Write domains to temporary input file
        for domain in domains:
            input_tmp.write(f"{domain}\n")
        input_tmp.flush()
        
        # Run dnsx
        result = subprocess.run(
            ["dnsx", "-l", input_tmp.name, "-o", output_file, "-silent", "-nc"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
            raise Exception(f"dnsx failed: {stderr}")
    
    # Read the output file and return as set
    resolved_domains = set()
    if Path(output_file).exists():
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    resolved_domains.add(line)
    
    return resolved_domains


def shufflednsExec(target, wordlist):
    """Run shuffledns DNS bruteforce and return subdomains as a set.
    
    Uses shuffledns to perform DNS bruteforce with the provided wordlist.
    Captures stdout directly instead of writing to file.
    """
    resolvers = "/home/d0b0/.config/shuffledns/resolvers.txt"
    result = subprocess.run(
        ["shuffledns", "-d", target, "-w", wordlist, "-r", resolvers, "-mode", "bruteforce",
         "-silent", "-nc", "-t", "1000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
        raise Exception(f"shuffledns failed: {stderr}")
    
    # Parse stdout lines into set
    subdomains = set()
    for line in result.stdout.decode().splitlines():
        line = line.strip()
        if line:
            subdomains.add(line)
    
    return subdomains


def subfinderExec(target_domain):
    """Run subfinder subdomain discovery and return subdomains as a set.
    
    Uses subfinder to perform passive subdomain enumeration.
    Captures stdout directly instead of writing to file.
    """
    result = subprocess.run(
        ["subfinder", "-d", target_domain, "-all", "-silent"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        raise Exception(f"subfinder failed: {result.stderr}")
    
    # Parse stdout lines into set
    subdomains = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            subdomains.add(line)
    
    return subdomains


def httpxExec(domains, target_domain, output_filename):
    """Probe subdomains with httpx and write results to file.
    
    Uses temporary file for input domains, then writes results directly to
    the specified output filename in the target directory.
    
    Returns:
        set: Empty set (for consistency with other tool functions)
    """
    output_file = f"{target_domain}/domain-recon/{output_filename}"
    
    # Create temporary input file
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=True) as input_tmp:
        # Write domains to temporary input file
        for domain in domains:
            input_tmp.write(f"{domain}\n")
        input_tmp.flush()
        
        # Run httpx
        result = subprocess.run(
            ["httpx", "-silent", "-l", input_tmp.name, "-fc", "404", "-sc", "-location", "-server", "-cdn", "-title",
             "-rl", "50", "-p", "80,443,8080,8000,8443", "-o", output_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
            raise Exception(f"httpx failed: {stderr}")
    
    return set()


def bbotExec(target_domain):
    """Run bbot subdomain enumeration (passive only) and return subdomains as a set.
    
    Uses bbot's -o flag to write to a temporary directory, then reads the
    subdomains output file and cleans up the directory.
    """
    import shutil
    
    # Create temporary directory path in target directory
    temp_dir = f"{target_domain}/domain-recon/bbot_tmp_{uuid.uuid4().hex[:8]}"
    
    try:
        result = subprocess.run(
            ["bbot", "-t", target_domain, "-p", "subdomain-enum",
             "-rf", "passive",
             "-n", target_domain, "-om", "subdomains",
             "-o", temp_dir, "-y", "-s"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
            raise Exception(f"bbot failed: {stderr}")
        
        # Read subdomains from BBOT output directory
        subdomains = set()
        bbot_output = Path(temp_dir) / "subdomains.txt"
        
        if bbot_output.exists():
            with open(bbot_output, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        subdomains.add(line)
        
        return subdomains
    
    finally:
        # Clean up temporary directory
        if Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


def crtshRequest(target_domain, max_retries=5):
    """Fetch subdomains from crt.sh API and return as a set.
    
    This function queries the crt.sh certificate transparency log API
    to discover subdomains associated with the target domain.
    """
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
            
            return subdomains
        
        except (HTTPError, URLError, json.JSONDecodeError) as e:
            if attempt < max_retries:
                time.sleep(2)
            else:
                raise
        except Exception as e:
            raise
