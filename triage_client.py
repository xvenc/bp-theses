import triage
from os import listdir, path
import sys
import getopt
import csv
import time
from src.pcap_downloader import Downloader
from src.sample_downloader import SampleDownloader
from src.general import bcolors, help, check_dir
from src.sample_uploader import Uploader

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"
report_dir = "reports/"
log_dir = "logs/"

# parse command line arguments
def arg_parse():
    command = {'--submit' : False, '--download' : False, '--now' : False, 
                '--get' : False, '--all' : False}
    option = {'-d' : [False,""], '-f' : [False,""], '-p' : [False, ""],
              '-o': [False, ""], '-m' : [False,""], '-l' : [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:o:m:l:", ["help", 
                                "submit", "download", "now", "get", "all"])
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

def get_families_from_logs(log_dir):
    family_dict = {}
    for filename in listdir(log_dir):
        family = path.splitext(filename)[0].split('_')[-1] 
        family_dict[family] = filename
    return family_dict



# MAIN
client = triage.Client(auth_api_key, public_api)
command,option = arg_parse()
d = Downloader(public_api+"v0/samples", auth_api_key, client)
sample_down = SampleDownloader()
uploader = Uploader(report_dir, client, log_dir)

# submit file or whole directory with files
if command['--submit']:
    if option['-d'][0] and path.isdir(option["-d"][1]):
        uploader.submit_directory(option, client, d, command, "")

    elif option['-f'][0] and path.isfile(option['-f'][1]):
        res = uploader.submit_file(option["-f"][1])

# Download pcap files from specified csv log file 
elif command['--download']:
    with open(option["-f"][1],mode='r') as csv_file:
        content = csv.DictReader(csv_file)
        d.download_from_csv(content,'behavioral1', option['-o'][1]) 

# download malware samples
elif command['--get']:
    samples_json, err = sample_down.get_query(option['-m'][1].lower(), 
                                                int(option['-l'][1]))
    if err:
        print(bcolors.FAIL + "Couldnt query samples for family " + 
        bcolors.ENDC + option['-m'][1])
        exit(1)

    if sample_down.download_samples(samples_json,option['-d'][1], option['-m'][1].lower()):
        print(bcolors.FAIL + "Couldnt download samples for family " + 
        bcolors.ENDC + option['-m'][1].lower())

# Download samples for specific family from malware bazaar
# then upload the samples to tria.ge to analysis and dowloading
# corresponding pcap files
elif command['--all']:
    pcap_dir = check_dir(option['-o'][1])
    data = read_lines(option['-m'][1])
    for family in data:
        # Download samples
        data_json, err = sample_down.get_query(family, int(option['-l'][1]))
        if err == 1:
            print(bcolors.FAIL + "Couldnt query samples for family " + 
            bcolors.ENDC + family)
            continue

        if sample_down.download_samples(data_json, option['-d'][1], family.lower()):
            print(bcolors.FAIL + "Couldnt download samples for family " + 
            bcolors.ENDC + family)
            continue

        # Submit samples
        if option['-d'][0] and path.isdir(option["-d"][1]):
            uploader.submit_directory(option, client, family.lower())

    print("Downloading pcap for uploaded samples...")
    time.sleep(300) 
    # after all samples were submitted wait and download samples
    family_dict = get_families_from_logs(log_dir)
    for family in data:
        if family.lower() in family_dict:
            d.download_samples_for_directory(option['-d'][1], 
            family.lower(), family_dict, report_dir, log_dir, pcap_dir)