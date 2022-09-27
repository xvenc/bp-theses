import triage
import requests
import os
import sys

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"
filename = "malware/KiffAppE2.bin"


def help():
    print("Usage: python3 triage_client [OPTION]\n")
    print("Options:")
    print("\t--help\tShow this help message and exits.")
    print("\t-d\tSpecifies directory with malware samples.")
    print("\t-f\tSpecifies one malware sample.")
    print("\t-p\tSets password for zip/tar protected files.")
    sys.exit(0)

#client = triage.Client(auth_api_key, public_api)
#name = os.path.basename(filename)
#response = client.submit_sample_file(name, open(filename, 'rb'), False, None, None)
#print(response)
