from assets import subdomain_enumeration, subdomain_permutation, probe
import os
import sys
from dotenv import load_dotenv

print(
    r"""

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
)

if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help", "-help", "help"}:
        print(
            "Usage: python3 pywebrecon.py domain.com /path/to/first/wordlist /path/to/second/wordlist"
        )
        print(
            "1st argument: Target domain\n2nd argument: First DNS bruteforce wordlist\n3rd argument: Second DNS bruteforce wordlist"
        )
        sys.exit(1)

    load_dotenv()
    target_domain = sys.argv[1]
    first_wordlist = os.getenv("FIRST_WORDLIST")
    second_wordlist = os.getenv("SECOND_WORDLIST")

    recon_dir = f"{target_domain}"

    try:
        os.makedirs(f"{recon_dir}/domain-recon")
    except FileExistsError as e:
        print(e, "\n")
        pass

    subdomain_enumeration(target_domain, recon_dir, first_wordlist, second_wordlist)
    subdomain_permutation(recon_dir)

    probe(f"{recon_dir}/domain-recon/")
