import triage
import requests
from os import path, listdir
import sys
import getopt

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"


def help():
    print("Usage: python3 triage_client [OPTION]\n")
    print("Options:")
    print("  --help\tShow this help message and exits.")
    print("  -d\tSpecifies directory with malware samples.")
    print("  -f\tSpecifies one malware sample.")
    print("  -p\tSets password for zip/tar protected files.")

def arg_parse() -> dict:
    arguments = {'--help' : False, '-d' : [False,""], '-f' : [False,""], '-p' : [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:p:", ["help"])
    except:
        help()
        sys.exit(1)

    # all arguments are correct so go through them
    for opt, arg in options:
        if opt == '--help':
            help()
            exit(0)
        else:
            arguments[opt][0] = True
            arguments[opt][1] = arg

    return arguments


def dir_exists(directory) -> bool:
    return path.exists(directory)

# log sample id and from witch directory its from
def log(sample_id : str, directory : str):
    pass


def submit_directory(directory, client : triage.Client):
    for filename in listdir(directory):
        f = path.join(directory, filename)
        # checking if it is a file
        if path.isfile(f):
            name = path.basename(f)
            response = client.submit_sample_file(name, open(f, 'rb'), False, None, None)
            print(response)


client = triage.Client(auth_api_key, public_api)
args = arg_parse()
if dir_exists(args["-d"][1]):
    submit_directory(args["-d"][1], client)
