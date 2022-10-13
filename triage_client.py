import triage
from os import path, listdir, walk
import sys
import getopt
from hashlib import md5
from pcap_downloader import Downloader
import csv
import time


public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"
log_dir = "logs/"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def help():
    print("Usage: python3 triage_client [COMMAND] [OPTION]\n")
    print("Command:")
    print("  --help\tShow this help message and exits.")
    print("  --submit\tSubmit file or whole directory to tria.ge")
    print("\n  Submit options:")
    print("\t-d\tSpecifies directory with malware samples.")
    print("\t-f\tSpecifies one malware sample.")
    print("\t-p\tSets password for zip/tar protected files.")
    print('\t-o\tSpecifies output directory name for dowloaded pcaps')
    print("\n  --download\tDownload all files from specified .csv file")
    print("\n  Download options:")
    print("\t-f\tSpecifies one .csv file with informations about samples.")
    print('\t-d\tSpecifies output directory name for dowloaded pcaps')
    print("Log files are automaticaly created. The file name is based on the input directory")

# parse command line arguments
def arg_parse():
    command = {'--submit' : False, '--download' : False, '--now' : False}
    option = {'-d' : [False,""], '-f' : [False,""], '-p' : [False, ""],
                 '-o': [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:p:o:", ["help", "submit", "download", "now"])
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

def create_file_name(directory):
    log_f = directory.replace('/','_')
    if log_f.endswith('_'):
        log_f = log_f[:-1] + ".csv"
    else:
        log_f = log_f + ".csv"
    return log_f


def write_header(file):
    header = ['Filename', 'Sample_id', 'mb5_hash']
    with open(log_dir+file, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(header)

# log sample id and from witch directory its from
def log(sample_id : str, filename : str, log_f : str):
    data = [filename, sample_id, get_hash(sample_id)]
    with open(log_dir+log_f, 'a') as f:
        # create the csv writer
        writer = csv.writer(f)
        # write a row to the csv file
        writer.writerow(data)

def check_submited(filepath : str) -> bool:
    for record in client.owned_samples():
        if md5(open(filepath,'rb').read()).hexdigest() == get_hash(record['id']):
            return False

    return True

# function to submit simple file using triage API
def submit_file(filepath : str):
    filename = path.basename(filepath)
    # check if file was already submitted
   # if check_submited(filepath):
   #     response = client.submit_sample_file(filename, open(filepath, 'rb'), False, None, None)
   #     return response

    response = client.submit_sample_file(filename, open(filepath, 'rb'), False, None, 'infected')
    return response

# function to submit all files from a directory
def submit_directory(opt, client : triage.Client, d, cmd):
    for subdir, dirs, files in walk(opt['-d'][1]):
        # check if directory contain files, not only other directories
        if files == []:
            continue
        print(bcolors.HEADER + "Submitting files from directory: " +bcolors.OKBLUE + f"{subdir}" + bcolors.ENDC)
        log_f= create_file_name(subdir)
        write_header(log_f)
        for file in files:        #listdir(opt["-d"][1]):
            f = path.join(subdir, file)
            # checking if it is a file
            if path.isfile(f):
                res = submit_file(f)
                print("Submitted malware: " + bcolors.OKBLUE + "{0}".format(res['filename']) + bcolors.ENDC)
                # download pcap files after sumbiting
                if cmd['--now']:
                    while True:
                        time.sleep(100)
                        if client.sample_by_id(res['id'])['status'] == 'reported':
                            log(res['id'], res['filename'], log_f)
                            d.download_sample(res['id'], 'behavioral1', opt['-o'][1]+subdir, res['filename'])
                            break;

# MAIN

client = triage.Client(auth_api_key, public_api)
command,option = arg_parse()
d = Downloader(public_api+"v0/samples", auth_api_key)


if command['--submit']:
    if option['-d'][0] and path.isdir(option["-d"][1]):
        submit_directory(option, client, d, command)

    elif option['-f'][0] and path.isfile(option['-f'][1]):
        res = submit_file(option["-f"][1])
        print(res)

elif command['--download']:
    #Pcap file downloader
    with open(option["-f"][1],mode='r') as csv_file:
        content = csv.DictReader(csv_file)
        d.download_from_csv(content,'behavioral1', option['-o'][1])

# List all owned_samples
#for r in client.owned_samples():
#    print("filename: {0} id: {1}".format(r['filename'], r['id']))
#
