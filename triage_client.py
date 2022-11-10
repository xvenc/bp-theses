import triage
from os import listdir, path
import sys
import getopt
import json
from src.pcap_downloader import Downloader
from src.sample_downloader import SampleDownloader
from src.general import bcolors, help
from src.sample_uploader import Uploader

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"
report_dir = "reports/"

# parse command line arguments
def arg_parse():
    command = {'--submit' : False, '--download' : False, '--now' : False, '--get' : False,
               '--all' : False}
    option = {'-d' : [False,""], '-f' : [False,""], '-p' : [False, ""],
              '-o': [False, ""], '-m' : [False,""], '-l' : [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:o:m:l:", ["help", "submit", "download", "now", "get", "all"])
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

# read lines from malware family file
def read_lines(file):
    data = list()
    if file != None:
        try:
            f = open(file,"r")
            data = f.readlines()
        except:
            data.append(file)
            print("Download one family " + file)
    else:
        print(bcolors.FAIL + "Family not specified" + bcolors.ENDC)
        exit(1)
    data = [l.strip() for l in data]
    return data

# check if directory end with '/'
def check_dir(directory):
    if directory[-1] != '/':
        directory += '/'
    return directory

# MAIN

client = triage.Client(auth_api_key, public_api)
command,option = arg_parse()
d = Downloader(public_api+"v0/samples", auth_api_key)
sample_down = SampleDownloader()
uploader = Uploader(report_dir, client)

# submit file or whole directory with files
if command['--submit']:
    if option['-d'][0] and path.isdir(option["-d"][1]):
        uploader.submit_directory(option, client, d, command, "")

    elif option['-f'][0] and path.isfile(option['-f'][1]):
        res = uploader.submit_file(option["-f"][1])
        print(res)
        if option['-o'][0]:
            uploader.download_pcap(client, res, "",option['-o'][1],d)

# Download pcap files from specified report directory
elif command['--download']:
    option['-d'][1] = check_dir(option['-d'][1])
    for file in listdir(option['-d'][1]):
        with open(option['-d'][1]+file) as json_file:
            data = json.load(json_file)
            d.download_from_report(data, option['-o'][1], file)

# download malware samples
elif command['--get']:
    samples_json, err = sample_down.get_query(option['-m'][1].lower(), int(option['-l'][1]))
    if err:
        print(bcolors.FAIL + "Couldnt query samples for family " + bcolors.ENDC + option['-m'][1])
        exit(1)

    if sample_down.download_samples(samples_json,option['-d'][1], option['-m'][1].lower()):
        print(bcolors.FAIL + "Couldnt download samples for family " + bcolors.ENDC + option['-m'][1].lower())

# Download samples for specific family from malware bazaar
# then upload the samples to tria.ge to analysis and dowloading
# corresponding pcap files
elif command['--all']:
    data = read_lines(option['-m'][1])
    for family in data:
        # Download samples
        data_json, err = sample_down.get_query(family, int(option['-l'][1]))
        if err == 1:
            print(bcolors.FAIL + "Couldnt query samples for family " + bcolors.ENDC + family)
            continue

        if sample_down.download_samples(data_json, option['-d'][1], family.lower()):
            print(bcolors.FAIL + "Couldnt download samples for family " + bcolors.ENDC + family)
            continue

        # Submit and download samples
        if option['-d'][0] and path.isdir(option["-d"][1]):
            uploader.submit_directory(option, client, d, command, family.lower())
