import os
import datetime
import shlex
import subprocess

def subdomain_enumeration(target_domain):

    timestamp = datetime.datetime.now()
    subdomain_list = []

    os.mkdir(f"{target_domain}_recon_{timestamp.day}-{timestamp.month}-{timestamp.year}")
    recon_directory = f"{target_domain}_recon_{timestamp.day}-{timestamp.month}-{timestamp.year}"


    # BEGIN SUBFINDER PROCESS
    print("=================================================================================")
    print("========================= Beginning Subfinder Enumeration =======================")
    print("\n")

    subfinder_domains = subprocess.check_output(["subfinder", "-d", f"{target_domain}", "-all", "-silent"])
    subfinder_domains = shlex.split(subfinder_domains.decode().rstrip())

    for domain in subfinder_domains:
        subdomain_list.append(domain)

    print("=================================================================================")
    print("=========================== Subfinder process done !! ===========================")
    print("\n")
    # END SUBFINDER PROCESS

    # BRUTEFORCE SUBDOMAINS
    wordlist_subdomains = input("Enter full path to the subdomain wordlist:\n")
    print("=================================================================================")
    print("======================= Beginning Bruteforcing Subdomains =======================")
    print("\n")
    puredns_domains = subprocess.check_output(["puredns", "bruteforce", f"{wordlist_subdomains}", "-q", f"{target_domain}"])
    puredns_domains = shlex.split(puredns_domains.decode().rstrip())
    for domain in puredns_domains:
        subdomain_list.append(domain)

    print("=================================================================================")
    print("======================== Bruteforcing subdomains done !! ========================")
    # END BRUTEFORCE PROCESS

    subdomain_list = list(dict.fromkeys(subdomain_list)) # Deduplicates the complete list of subdomains

    ## Write the subdomains to a file
    for sub in subdomain_list:
        with open(f"{recon_directory}/all_subdomains.txt", "a") as f:
            f.write(f"{sub}\n")
        f.close()