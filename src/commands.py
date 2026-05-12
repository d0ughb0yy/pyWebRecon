import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DOCKER_USER = f"{os.getuid()}:{os.getgid()}"

REQUIRED_IMAGES = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/shuffledns:latest",
    "projectdiscovery/dnsx:latest",
    "projectdiscovery/httpx:latest",
    "blacklanternsecurity/bbot:latest",
]


def pullDockerImages():
    missing = []
    for image in REQUIRED_IMAGES:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            missing.append(image)

    if missing:
        print("\nPulling required Docker images (this may take a while depending on your connection)...")
        for image in missing:
            print(f"  Pulling {image}...")
            result = subprocess.run(
                ["docker", "pull", image],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if result.returncode != 0:
                print(f"  Failed to pull {image}: {result.stderr.strip()}")
                raise Exception(f"Docker image pull failed: {image}")
        print("All images ready!\n")


def dnsxExec(domains, target_domain, output_filename):
    """Resolve subdomains with dnsx via Docker and return resolved domains as a set."""
    output_file = f"{target_domain}/domain-recon/{output_filename}"
    abs_output_file = os.path.abspath(output_file)
    abs_output_dir = os.path.abspath(f"{target_domain}/domain-recon")

    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".txt", delete=True
    ) as input_tmp:
        input_tmp.write("\n".join(domains) + "\n")
        input_tmp.flush()

        abs_input = os.path.abspath(input_tmp.name)
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                "dnsx",
                "--user",
                DOCKER_USER,
                "-v",
                f"{abs_input}:{abs_input}:ro",
                "-v",
                f"{abs_output_dir}:{abs_output_dir}",
                "projectdiscovery/dnsx:latest",
                "-l",
                abs_input,
                "-o",
                abs_output_file,
                "-silent",
                "-nc",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=1800,
        )
        if result.returncode != 0:
            raise Exception(f"dnsx failed: {result.stderr.decode()}")

    resolved_domains = set()
    if Path(abs_output_file).exists():
        with open(abs_output_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    resolved_domains.add(line)

    return resolved_domains


def shufflednsExec(target, wordlist):
    """Run shuffledns DNS bruteforce via Docker and return subdomains as a set."""
    abs_wordlist = os.path.abspath(wordlist)
    resolvers = os.path.expanduser("~/.config/shuffledns/resolvers.txt")
    abs_resolvers = os.path.abspath(resolvers)

    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                "shuffledns",
                "-v",
                f"{abs_wordlist}:{abs_wordlist}:ro",
                "-v",
                f"{abs_resolvers}:{abs_resolvers}:ro",
                "projectdiscovery/shuffledns:latest",
                "-d",
                target,
                "-w",
                abs_wordlist,
                "-r",
                abs_resolvers,
                "-silent",
                "-t",
                "1000",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=28800,
        )
    except subprocess.TimeoutExpired:
        subprocess.run(
            ["docker", "kill", "shuffledns"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        raise Exception(
            "shuffledns timed out — try using smaller wordlists "
            "or fewer wordlist files"
        )

    if result.returncode != 0:
        raise Exception(f"shuffledns failed: {result.stderr}")

    subdomains = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            subdomains.add(line)

    return subdomains


def subfinderExec(target_domain):
    """Run subfinder subdomain discovery via Docker and return subdomains as a set."""
    config_path = os.path.expanduser("~/.config/subfinder/config.yaml")

    cmd = [
        "docker",
        "run",
        "--rm",
        "--name",
        "subfinder",
    ]
    if os.path.exists(config_path):
        abs_config = os.path.abspath(config_path)
        cmd += ["-v", f"{abs_config}:/root/.config/subfinder/config.yaml:ro"]
    cmd += [
        "projectdiscovery/subfinder:latest",
        "-d",
        target_domain,
        "-all",
        "-silent",
    ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=1800,
    )
    if result.returncode != 0:
        raise Exception(f"subfinder failed: {result.stderr}")

    subdomains = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            subdomains.add(line)

    return subdomains


def httpxExec(domains, target_domain, output_filename):
    """Probe subdomains with httpx via Docker and write results to file."""
    output_file = f"{target_domain}/domain-recon/{output_filename}"
    abs_output_file = os.path.abspath(output_file)
    abs_output_dir = os.path.abspath(f"{target_domain}/domain-recon")

    with tempfile.NamedTemporaryFile(
        mode="w+", suffix=".txt", delete=True
    ) as input_tmp:
        input_tmp.write("\n".join(domains) + "\n")
        input_tmp.flush()

        abs_input = os.path.abspath(input_tmp.name)
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                "httpx",
                "--user",
                DOCKER_USER,
                "-v",
                f"{abs_input}:{abs_input}:ro",
                "-v",
                f"{abs_output_dir}:{abs_output_dir}",
                "projectdiscovery/httpx:latest",
                "-silent",
                "-l",
                abs_input,
                "-fc",
                "404",
                "-sc",
                "-location",
                "-server",
                "-cdn",
                "-title",
                "-ip",
                "-rl",
                "50",
                "-p",
                "80,443,8080,8000,8443",
                "-o",
                abs_output_file,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=1800,
        )
        if result.returncode != 0:
            raise Exception(f"httpx failed: {result.stderr.decode()}")

    return set()


def bbotExec(target_domain):
    """Run BBot subdomain enumeration via Docker and return subdomains as a set."""
    bbot_dir = os.path.expanduser("~/.bbot")
    config_dir = os.path.expanduser("~/.config/bbot")

    cmd = ["docker", "run", "--rm", "--name", "bbot"]

    os.makedirs(bbot_dir, exist_ok=True)
    cmd += ["-v", f"{os.path.abspath(bbot_dir)}:/root/.bbot"]

    if os.path.exists(config_dir):
        cmd += ["-v", f"{os.path.abspath(config_dir)}:/root/.config/bbot"]

    cmd += [
        "blacklanternsecurity/bbot:latest",
        "-t", target_domain,
        "-p", "subdomain-enum",
        "-rf", "passive",
        "-s",
        "--brief",
    ]

    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3600
    )
    if result.returncode != 0:
        raise Exception(f"bbot failed: {result.stderr}")

    subdomains = set()
    for line in result.stdout.splitlines():
        line = line.strip().lower()
        if line:
            subdomains.add(line)

    return subdomains


def crtshRequest(target_domain, max_retries=5):
    """Fetch subdomains from crt.sh API and return as a set.

    This function queries the crt.sh certificate transparency log API
    to discover subdomains associated with the target domain.
    """
    target_domain = target_domain.lstrip(".").lower()
    url = f"https://crt.sh/?q={target_domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://crt.sh/",
    }

    for attempt in range(1, max_retries + 1):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())

            subdomains = set()
            for item in data:
                for name in item.get("name_value", "").splitlines():
                    name = name.strip().lower()
                    if name and (
                        name.endswith(f".{target_domain}") or name == target_domain
                    ):
                        subdomains.add(name[2:] if name.startswith("*.") else name)

            return subdomains

        except (HTTPError, URLError, json.JSONDecodeError):
            if attempt < max_retries:
                backoff = 2**attempt
                time.sleep(backoff)
            else:
                raise
        except Exception:
            raise
