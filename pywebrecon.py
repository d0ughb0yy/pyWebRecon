#!/usr/bin/env python3

from src.assets import *
from src.commands import *
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

    for wl in wordlists:
        if not os.path.exists(wl):
            parser.error(f"wordlist file not found: {wl}")

    print(BANNER)
    
    os.makedirs(f"{target_domain}/domain-recon", exist_ok=True)

    # Stage 1: Gather subdomains (concurrent enumeration)
    all_subdomains = subdomainEnumeration(target_domain, wordlists)
    
    # Stage 2: Process subdomains (resolve and scan)
    if all_subdomains:
        processingSubdomains(target_domain, all_subdomains)

    console.print()
    cleanup(target_domain)
    info(f"Scan complete. Results saved to {target_domain}/domain-recon/")
