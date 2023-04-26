"""
ml_classifier.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Main modul for downloading malware samples, sending them to analysis and downloading all reports and pcap files
"""

import triage
from os import  path
import csv
import time
from src.pcap_downloader import Downloader
from src.sample_downloader import SampleDownloader
from src.general import *
from src.sample_uploader import Uploader

public_api = "https://api.tria.ge/"
auth_api_key = "349a1f88ad1e2aee63e6e304a1400ca1af82e423"
report_dir = "reports/"
log_dir = "logs/"
pcap_dir = "pcaps/"
network_dir = "network/"
malware_dir = "malware/"


# MAIN
client = triage.Client(auth_api_key, public_api)
command,option = arg_parse()
d = Downloader(public_api+"v0/samples/", auth_api_key, client)
sample_down = SampleDownloader()
uploader = Uploader(client, log_dir)

# submit file or whole directory with files
if command['--submit']:
    if option['-d'][0] and path.isdir(option["-d"][1]):
        uploader.submit_directory(option, client, d, command, "", "")

    elif option['-f'][0] and path.isfile(option['-f'][1]):
        res = uploader.submit_file(option["-f"][1])

# Download pcap files from specified csv log file 
elif command['--download']:
    with open(option["-f"][1],mode='r') as csv_file:
        content = csv.DictReader(csv_file)
        d.download_from_csv(content,'behavioral1', option['-o'][1], "1")
        d.download_from_csv(content, 'behavioral2', option['-o'][1], "2") 

# download malware samples
elif command['--get']:
    samples_json, err = sample_down.get_query(option['-m'][1].lower(), 
                                                int(option['-l'][1]))
    if err:
        print(bcolors.FAIL + "Couldnt query samples for family " + 
        bcolors.ENDC + option['-m'][1])
        exit(1)

    if sample_down.download_samples(samples_json,option['-o'][1], option['-m'][1].lower()):
        print(bcolors.FAIL + "Couldnt download samples for family " + 
        bcolors.ENDC + option['-m'][1].lower())

# Download samples for specific family from malware bazaar
# then upload the samples to tria.ge to analysis and dowloading
# corresponding pcap files
elif command['--all']:
    output = check_dir(option['-o'][1])
    # Read malware family names
    data = read_lines(option['-m'][1])
    # Create output folder structure
    create_folders(output, malware_dir, pcap_dir, report_dir, network_dir) 
    malware_dir = path.join(output, malware_dir)
    report_dir = path.join(output, report_dir)
    pcap_dir = path.join(output, pcap_dir)
    network_dir = path.join(output, network_dir)

    for family in data:
        # Download samples
        data_json, err = sample_down.get_query(family, int(option['-l'][1]))
        if err == 1:
            print(bcolors.FAIL + "Couldnt query samples for family " +
            bcolors.ENDC + family)
            continue
        family = family.lower().replace(" ","")
        if sample_down.download_samples(data_json, malware_dir, family):
            print(bcolors.FAIL + "Couldnt download samples for family " +
            bcolors.ENDC + family)
            continue

        # Submit samples
        if path.isdir(malware_dir):
            uploader.submit_directory(malware_dir, client, family, report_dir, network_dir)


    print("Downloading pcaps and reports for uploaded samples...")
    time.sleep(300)
    # after all samples were submitted wait and download samples
    family_dict = get_families_from_logs(log_dir)
    for family in data:
        family = family.lower().replace(" ","")
        if family in family_dict:
            d.download_samples_for_directory(malware_dir,
            family, family_dict, report_dir, log_dir, pcap_dir, network_dir)
