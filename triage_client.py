import triage
from os import path, walk
import sys
import getopt
import csv
import time
import json
from src.pcap_downloader import Downloader
from src.sample_downloader import SampleDownloader
from src.general import bcolors, help
from src.report import create_folder, create_file, create_report, create_malware_folder, check_downloaded

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"
log_dir = "logs/"
report_dir = "reports/"

# parse command line arguments
def arg_parse():
    command = {'--submit' : False, '--download' : False, '--now' : False, '--get' : False,
               '--all' : False}
    option = {'-d' : [False,""], '-f' : [False,""], '-p' : [False, ""],
              '-o': [False, ""], '-m' : [False,""], '-l' : [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:p:o:m:l:", ["help", "submit", "download", "now", "get", "all"])
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
            print("Download one family "+file)
    else:
        print(bcolors.FAIL + "Family not specified" + bcolors.ENDC)
        exit(1)
    data = [l.strip() for l in data]
    return data


# function to submit simple file using triage API
def submit_file(filepath : str):
    filename = path.basename(filepath)
    response = ""
    if path.isfile(filepath):
        try:
            response = client.submit_sample_file(filename, open(filepath, 'rb'), False, None, 'infected')
        except:
            print(bcolors.FAIL + "Error: Couldnt sent http request")
    return response

# function to wait for the analysis to be done and then download the pcap
def download_pcap(client, res, pcap_dir, subdir, d):
    print("Downloading",end="")
    while True:
        try:
            status = client.sample_by_id(res['id'])['status']
        except:
            print(bcolors.FAIL + "Couldnt download pcap." + bcolors.ENDC)
            break;
        # check if sample analysis was reported
        if  status == 'reported':
            print()
            d.download_sample(res['id'], 'behavioral1', pcap_dir+subdir, res['filename'])
            break;
        else:
            print(".", end="")
            time.sleep(60)

def check_dir(directory):
    if directory[-1] != '/':
        directory += '/'
    return directory

def report(client, res, report_dir, report_file):
    try:
        report = client.overview_report(res['id'])
    except:
        print(bcolors.FAIL + "Couldnt download report." + bcolors.ENDC)
        return
     
    create_report(report, report_file, report_dir) 


# function to submit all files from a directory
def submit_directory(opt, client, d, cmd, family):
    malware_dir = check_dir(opt['-d'][1])
    pcap_dir = check_dir(opt['-o'][1])
    create_folder(report_dir)
    for subdir, dirs, files in walk(malware_dir+family):
        # check if directory contain files, not only other directories
        if files == []:
            continue
        print(bcolors.HEADER + "Submitting files from directory: " +bcolors.OKBLUE + f"{subdir}" + bcolors.ENDC)
        create_malware_folder(report_dir+subdir) #NEW
        # iterate trough files in directory
        for file in files:
            f = path.join(subdir, file)
            # checking if it is a file and wasnt already downloaded
            if path.isfile(f) and not check_downloaded(report_dir+subdir, f):
                res = submit_file(f)
                if res == "":
                    continue
                print("Submitted malware: " + bcolors.OKBLUE + "{0}".format(res['filename']) + bcolors.ENDC)

                report_f = create_file(path.splitext(res['filename'])[0])

                # download pcap files after sumbiting
                if cmd['--now']:
                    download_pcap(client, res, pcap_dir, subdir, d)
                    report(client, res, report_dir+subdir, report_f) 
            else:
                print(bcolors.OKBLUE + file + bcolors.ENDC + bcolors.BOLD + " was already downloaded")
    return

# MAIN

client = triage.Client(auth_api_key, public_api)
command,option = arg_parse()
d = Downloader(public_api+"v0/samples", auth_api_key)
sample_down = SampleDownloader()

# submit file or whole directory with files
if command['--submit']:
    if option['-d'][0] and path.isdir(option["-d"][1]):
        submit_directory(option, client, d, command, "")

    elif option['-f'][0] and path.isfile(option['-f'][1]):
        res = submit_file(option["-f"][1])
        print(res)
        if option['-o'][0]:
            download_pcap(client, res, "","",option['-o'][1],"",d)

# Download pcap files from specified csv file
elif command['--download']:
    with open(option["-f"][1],mode='r') as csv_file:
        content = csv.DictReader(csv_file)
        d.download_from_csv(content,'behavioral1', option['-o'][1])

# download malware samples
elif command['--get']:
    samples_json, err = sample_down.get_query(option['-m'][1], int(option['-l'][1]))
    if err:
        print(bcolors.FAIL + "Couldnt query samples for family " + bcolors.ENDC + option['-m'][1])
        exit(1)
    if sample_down.download_samples(samples_json,option['-d'][1], option['-m'][1]):
        print(bcolors.FAIL + "Couldnt download samples for family " + bcolors.ENDC + option['-m'][1])

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
            #exit(1)
        if sample_down.download_samples(data_json, option['-d'][1], family):
            print(bcolors.FAIL + "Couldnt download samples for family " + bcolors.ENDC + family)
            continue
        # Submit and download samples
        if option['-d'][0] and path.isdir(option["-d"][1]):
            submit_directory(option, client, d, command, family)
