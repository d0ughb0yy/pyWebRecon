import os
import datetime
import shlex
import subprocess

# timestamp = datetime.datetime.now()

# RECON_DIR = f"recon_{timestamp.day}-{timestamp.month}-{timestamp.year}"

def subdomain_enumeration(target_domain, recon_dir):
    '''Uses Subfinder and Puredns CLI tools to enumerate subdomains for a given target'''

    subdomain_list = []
    # os.mkdir(RECON_DIR)

    #BEGIN SUBFINDER PROCESS
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
    print("\n")
    print("=================================================================================")
    print("======================= Beginning Bruteforcing Subdomains =======================")
    print("\n")
    puredns_results = subprocess.check_output(["puredns", "bruteforce", f"{wordlist_subdomains}" , f"{target_domain}", "-l", "500", "-q"])
    puredns_results = shlex.split(puredns_results.decode().rstrip())
    for domain in puredns_results:
        subdomain_list.append(domain)

    print("=================================================================================")
    print("======================== Bruteforcing subdomains done !! ========================")
    print("\n")
    # END BRUTEFORCE PROCESS

    subdomain_list = list(dict.fromkeys(subdomain_list)) # Deduplicates the complete list of subdomains

    ## Write the subdomains to a file
    for sub in subdomain_list:
        with open(f"{recon_dir}/all_subdomains.txt", "a") as f:
            f.write(f"{sub}\n")
        f.close()

def subdomain_permutation(recon_dir):
    '''Uses gotator to permutate subdomains'''

    permutated_subdomains = []

    print("=================================================================================")
    print("======================== Beginning Subdomain Permutation ========================")
    print("\n")

    gotator_results = subprocess.check_output(["gotator", "-sub", f"{recon_dir}/all_subdomains.txt" , "-md"])
    gotator_results = shlex.split(gotator_results.decode().rstrip())

    for domain in gotator_results:
        permutated_subdomains.append(domain)
    
    with open(f"{recon_dir}/permutated_subdomains.txt", "w") as f:
        for subdomain in permutated_subdomains:
            f.write(f"{subdomain}\n")
        f.close()

    print("=================================================================================")
    print("============================== Permutations done !! =============================")
    print("\n")