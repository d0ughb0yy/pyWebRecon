#!/usr/bin/env python3
from src.assets import *
from src.commands import *
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
    print(BANNER)

    parser = argparse.ArgumentParser(description="Automation script for bug bounty hunters")
    parser.add_argument("-d", "--domain", help="Target")
    parser.add_argument("-fw", "--first-wordlist", help="First shuffledns wordlist path")
    parser.add_argument("-sw", "--second-wordlist", help="Second shuffledns wordlist path")

    args = parser.parse_args()
    target_domain = args.domain
    first_wordlist = args.first_wordlist
    second_wordlist = args.second_wordlist

    os.makedirs(f"{target_domain}/domain-recon", exist_ok=True)

    subdomain_enumeration(target_domain, first_wordlist, second_wordlist)
    subdomain_resolve(target_domain)
    subdomain_permutation(target_domain)
    cleanup(target_domain)