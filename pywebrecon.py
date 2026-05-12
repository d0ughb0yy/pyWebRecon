#!/usr/bin/env python3

import re
from src.assets import subdomainEnumeration, processingSubdomains
from src.commands import pullDockerImages
from src.output import info, console
import os
import argparse

BANNER = r"""
                      /$$      /$$           /$$       /$$$$$$$                                         
                     | $$  /$ | $$          | $$      | $$__  $$                                        
   /$$$$$$  /$$   /$$| $$ /$$$| $$  /$$$$$$ | $$$$$$$ | $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$ 
  /$$__  $$| $$  | $$| $$/$$ $$ $$ /$$__  $$| $$__  $$| $$$$$$$/ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$
 | $$  \ $$| $$  | $$| $$$$_  $$$$| $$$$$$$$| $$  \ $$| $$__  $$| $$$$$$$$| $$      | $$  \ $$| $$  \ $$
 | $$  | $$| $$  | $$| $$$/ \  $$$| $$_____/| $$  | $$| $$  \ $$| $$_____/| $$      | $$  | $$| $$  | $$
 | $$$$$$$/|  $$$$$$$| $$/   \  $$|  $$$$$$$| $$$$$$$/| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$
 | $$____/  \____  $$|__/     \__/ \_______/|_______/ |__/  |__/ \_______/ \_______/ \______/ |__/  |__/
 | $$       /$$  | $$                                                                                   
 | $$      |  $$$$$$/                                                                                   
 |__/       \______/                                                                                   
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automation script for bug bounty hunters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pywebrecon.py -d example.com -w wordlist1.txt
  python3 pywebrecon.py -d example.com -w wordlist1.txt wordlist2.txt
  python3 pywebrecon.py -d example.com -w ~/wordlists/subdomains.txt ~/wordlists/names.txt ~/wordlists/more.txt
"""
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", nargs="+", required=True, help="Shuffledns wordlist path(s) (one or more)")

    args = parser.parse_args()
    
    target_domain = args.domain
    wordlists = args.wordlist

    # Validate domain format
    domain_pattern = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$')
    if not domain_pattern.match(target_domain):
        parser.error(f"invalid domain format: {target_domain}")

    for wl in wordlists:
        if not os.path.exists(wl):
            parser.error(f"wordlist file not found: {wl}")
        if not os.access(wl, os.R_OK):
            parser.error(f"wordlist file not readable: {wl}")
        if os.path.getsize(wl) == 0:
            parser.error(f"wordlist file is empty: {wl}")

    print(BANNER)

    pullDockerImages()
    
    os.makedirs(f"{target_domain}/domain-recon", exist_ok=True)

    # Stage 1: Gather subdomains (concurrent enumeration)
    all_subdomains = subdomainEnumeration(target_domain, wordlists)
    
    # Stage 2: Process subdomains (resolve and scan)
    if all_subdomains:
        processingSubdomains(target_domain, all_subdomains)
    else:
        console.print("[yellow]No subdomains discovered by any enumeration tool[/yellow]")

    console.print()
    info(f"Scan complete. Results saved to {target_domain}/domain-recon/")
