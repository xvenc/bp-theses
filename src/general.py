"""
general.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Modul with class for colors of text, help function and other basic functions (argument parsing, read file lines) 
"""


from pathlib import Path
from os import listdir, path
import getopt
import sys

# Colors for preattier output
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

# Simple help
def help():
    print("Usage: python3 triage_client [COMMAND] [OPTION]\n")
    print("Command:")
    print(bcolors.OKBLUE+"  --help"+ bcolors.ENDC +"\tShow this help message and exits.")
    print(bcolors.OKBLUE+"  --submit"+bcolors.ENDC+"\tSubmit file or whole directory to tria.ge")
    print(bcolors.OKCYAN+"  Options for submit:"+bcolors.ENDC)
    print("\t-d\tSpecifies directory with malware samples.")
    print("\t-f\tSpecifies one malware sample.")
    print('\t-o\tSpecifies output directory name for dowloaded pcaps')
    print(bcolors.OKBLUE+"\n  --download"+bcolors.ENDC+"\tDownload all pcaps for specified csv file")
    print(bcolors.OKCYAN+"  Options for download:"+bcolors.ENDC)
    print("\t-f\tSpecifies one csv file created by --submit command or --all command.")
    print('\t-o\tSpecifies output directory name for dowloaded pcaps')
    print(bcolors.OKBLUE+"\n  --get"+bcolors.ENDC+"\tDownloads n malware samples of specified family")
    print(bcolors.OKCYAN+"  Options for get:"+bcolors.ENDC)
    print("\t-m\tSpecifies malware family. If the family consist of 2 words, it needs to be in \"\"(\"Smoke Loader\") ")
    print("\t-l\tSpecifies how many samples of given family we want.")
    print('\t-o\tSpecifies output directory name for dowloaded samples')
    print(bcolors.OKBLUE+"\n  --all"+bcolors.ENDC+"\tDownloads n malware samples of specified family and runs analysis and than stores the pcap files")
    print(bcolors.OKCYAN+"  Options for all:"+bcolors.ENDC)
    print("\t-m\tSpecifies malware family. Or .txt file with malware family names each on new line of the file")
    print("\t-l\tSpecifies how many samples of given family we want.")
    print('\t-o\tSpecifies output directory name. In this directory will be created folders malware, pcaps and reports')
    print("\nLog and report files are automaticaly created. The file name is based on the input directory")


# check if directory end with '/'
def check_dir(directory):
    if directory[-1] != '/':
        directory += '/'
    return directory

# Create folder structure
def create_folders(out_dir, malware, pcaps, reports, network):
    Path(path.join(out_dir, malware)).mkdir(parents=True, exist_ok=True)
    Path(path.join(out_dir,pcaps)).mkdir(parents=True, exist_ok=True)
    Path(path.join(out_dir,reports)).mkdir(parents=True, exist_ok=True)
    Path(path.join(out_dir,network)).mkdir(parents=True, exist_ok=True)

# Create one directory with specified name
def create_folder(directory):
    if directory[-1] != '/':
            directory += '/'
    if not path.isdir(directory):
        Path(directory).mkdir(parents=True, exist_ok=True)

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

# Extract family names from log files
def get_families_from_logs(log_dir):
    family_dict = {}
    for filename in listdir(log_dir):
        family = path.splitext(filename)[0].split('_')[-1] 
        family_dict[family] = filename
    return family_dict

