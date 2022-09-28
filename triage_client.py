import triage
from os import path, listdir
import sys
import getopt
from hashlib import md5

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"


def help():
    print("Usage: python3 triage_client [OPTION]\n")
    print("Options:")
    print("  --help\tShow this help message and exits.")
    print("  -d\tSpecifies directory with malware samples.")
    print("  -f\tSpecifies one malware sample.")
    print("  -p\tSets password for zip/tar protected files.")

# parse command line arguments
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

    # MBY TODO multiple files set
    if arguments["-f"][0] and not arguments['-d'][0]:
        pass

    return arguments

# return md5 hash of the submited sample
def get_hash(sample_id: str) -> str:
    return client.overview_report(sample_id)['sample']['md5']


# log sample id and from witch directory its from
def log(sample_id : str, directory : str):
    pass

def check_submited(filepath : str) -> bool:
    for record in client.owned_samples():
        if md5(open(filepath,'rb').read()).hexdigest() == get_hash(record['id']):
            return False

    return True

# function to submit simple file using triage API
def submit_file(filepath : str):
    filename = path.basename(filepath)
    if check_submited(filepath):
        response = client.submit_sample_file(filename, open(filepath, 'rb'), False, None, None)
        return response
    return "already submited"

# function to submit all files from a directory
def submit_directory(directory, client : triage.Client):
    for filename in listdir(directory):
        f = path.join(directory, filename)
        # checking if it is a file
        if path.isfile(f):
            res = submit_file(f)

# MAIN

client = triage.Client(auth_api_key, public_api)
args = arg_parse()

if args['-d'][0] and path.isdir(args["-d"][1]):
    submit_directory(args["-d"][1], client)

elif args['-f'][0] and path.isfile(args['-f'][1]):
    res = submit_file(args["-f"][1])
    print(res)


