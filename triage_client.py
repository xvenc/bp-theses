import triage
from os import path, walk
import sys
import getopt
from pcap_downloader import Downloader
from sample_downloader import SampleDownloader
import time
from general import bcolors, help
from csv_writer import create_file_name, write_header, log
import csv

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"
log_dir = "logs/"

# parse command line arguments
def arg_parse():
    command = {'--submit' : False, '--download' : False, '--now' : False, '--get' : False,
               '--all' : False}
    option = {'-d' : [False,""], '-f' : [False,""], '-p' : [False, ""],
              '-o': [False, ""], '-m' : [False,""], '-l' : [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:p:o:m:l:", ["help", "submit", "download", "now", "get"])
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

# function to submit simple file using triage API
def submit_file(filepath : str):
    filename = path.basename(filepath)
    try:
        response = client.submit_sample_file(filename, open(filepath, 'rb'), False, None, 'infected')
    except:
        print(bcolors.FAIL + "Error: Couldnt set http request")
        exit(1)
    return response

# function to submit all files from a directory
def submit_directory(opt, client, d, cmd):
    for subdir, dirs, files in walk(opt['-d'][1]):
        # check if directory contain files, not only other directories
        if files == []:
            continue
        print(bcolors.HEADER + "Submitting files from directory: " +bcolors.OKBLUE + f"{subdir}" + bcolors.ENDC)
        log_f= create_file_name(subdir)
        write_header(log_f, log_dir)
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
                            log(res['id'], res['filename'], log_f, client, log_dir)
                            d.download_sample(res['id'], 'behavioral1', opt['-o'][1]+subdir, res['filename'])
                            break;

# MAIN

client = triage.Client(auth_api_key, public_api)
command,option = arg_parse()
d = Downloader(public_api+"v0/samples", auth_api_key)
sample_down = SampleDownloader()

# submit file or whole directory with files
if command['--submit']:
    if option['-d'][0] and path.isdir(option["-d"][1]):
        submit_directory(option, client, d, command)

    elif option['-f'][0] and path.isfile(option['-f'][1]):
        res = submit_file(option["-f"][1])
        print(res)

# Download pcap files from specified csv file
elif command['--download']:
    with open(option["-f"][1],mode='r') as csv_file:
        content = csv.DictReader(csv_file)
        d.download_from_csv(content,'behavioral1', option['-o'][1])

# download malware samples
elif command['--get']:
    samples_json = sample_down.get_query(option['-m'][1], int(option['-l'][1]))
    sample_down.download_samples(samples_json,option['-o'][1], option['-m'][1])

# Download samples for specific family from malware bazaar
# then upload the samples to tria.ge to analysis and dowloading
# corresponding pcap files
# TODO change options
elif command['--all']:
    # Download samples
    data_json = sample_down.get_query(option['-m'][1], int(option['-l'][1]))
    sample_down.download_samples(data_json, option['-o'][1], option['-m'][1])
    # Submit and download samples
    if option['-d'][0] and path.isdir(option["-d"][1]):
        submit_directory(option, client, d, command)


