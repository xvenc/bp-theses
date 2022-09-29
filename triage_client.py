import triage
from os import path, listdir
import sys
import getopt
from hashlib import md5
from pcap_downloader import Downloader
import csv

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"


def help():
    print("Usage: python3 triage_client [COMMAND] [OPTION]\n")
    print("Command:")
    print("  --help\tShow this help message and exits.")
    print("  --submit\tSubmit file or whole directory to tria.ge")
    print("\n  Submit options:")
    print("\t-d\tSpecifies directory with malware samples.")
    print("\t-f\tSpecifies one malware sample.")
    print("\t-p\tSets password for zip/tar protected files.")
    print("\n  --download\tDownload all files from specified .csv file")
    print("\n  Download options:")
    print("\t-f\tSpecifies one .csv file with informations about samples.")
    print('\t-d\tSpecifies output directory name for dowloaded pcaps')

# parse command line arguments
def arg_parse():
    command = {'--submit' : False, '--download' : False}
    option = {'-d' : [False,""], '-f' : [False,""], '-p' : [False, ""],
                 '-o': [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:p:o:", ["help", "submit", "download"])
    except:
        help()
        sys.exit(1)

    # all arguments are correct so go through them
    for opt, arg in options:
        if opt == '--help':
            help()
            exit(0)
        elif opt in option:
            option[opt][0] = True
            option[opt][1] = arg
        elif opt in command:
            command[opt] = True

    if command['--submit'] and command['--download']:
        sys.exit(1)

    return command,option

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
command,option = arg_parse()

if command['--submit']:
    print("submit")
    if option['-d'][0] and path.isdir(option["-d"][1]):
        submit_directory(option["-d"][1], client)

    elif option['-f'][0] and path.isfile(option['-f'][1]):
        res = submit_file(option["-f"][1])
        print(res)

elif command['--download']:
    #Pcap file downloader
    d = Downloader(public_api+"v0/samples", auth_api_key)
    with open(option["-f"][1],mode='r') as csv_file:
        content = csv.DictReader(csv_file)
        d.download(content,'behavioral1', option['-o'][1])

# List all owned_samples
#for r in client.owned_samples():
#    print("filename: {0} id: {1}".format(r['filename'], r['id']))
#
## Logging
#with open('logs/test.csv', 'w') as f:
#    # create the csv writer
#    writer = csv.writer(f)
#
#    header = ['Filename', 'Sample_id', 'mb5_hash']
#    data = ['KiffAppE2.bin', '220928-zc965aabdn', 'db5cc5204a082888533280e4cb9099b0']
#    data2 = ['220925-wx71qaghdr_pw_infected.zip', '220927-yhag1sfdgr', '66b39f02f8aab03e7d6b0cdc63eb2718']
#    # write a row to the csv file
#    writer.writerow(header)
#    writer.writerow(data)
#    writer.writerow(data2)
