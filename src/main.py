import os
import datetime
import shlex
import subprocess

target_domain = input(f"What is the target domain?\n")
timestamp = datetime.datetime.now()
subdomain_list = []

os.mkdir(f"{target_domain}_recon_{timestamp.day}-{timestamp.month}-{timestamp.year}")
recon_directory = f"{target_domain}_recon_{timestamp.day}-{timestamp.month}-{timestamp.year}"


# BEGIN SUBFINDER PROCESS
subfinder_domains = subprocess.check_output(["subfinder", "-d", f"{target_domain}", "-all", "-silent"])
subfinder_domains = shlex.split(subfinder_domains.decode().rstrip())

for domain in subfinder_domains:
    subdomain_list.append(domain)
print("Subfinder process done !!")
# END SUBFINDER PROCESS

# BRUTEFORCE SUBDOMAINS
wordlist_subdomains = input("Enter full path to the subdomain wordlist:\n")
print("Beginning bruteforcing...")
puredns_domains = subprocess.check_output(["puredns", "bruteforce", f"{wordlist_subdomains}", "-q", f"{target_domain}"])
puredns_domains = shlex.split(puredns_domains.decode().rstrip())
for domain in puredns_domains:
    subdomain_list.append(domain)
print("Bruteforce finished !!")
# END BRUTEFORCE PROCESS

subdomain_list = list(dict.fromkeys(subdomain_list)) # Deduplicate the complete list of subdomains


