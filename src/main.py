import os
import datetime
import requests
import threading

target_domain = input(f"What is the target domain?\n")
timestamp = datetime.datetime.now()

os.mkdir(f"{target_domain}_recon_{timestamp.day}-{timestamp.month}-{timestamp.year}")

subfinder_domains = os.system('subfinder')
print(subfinder_domains)