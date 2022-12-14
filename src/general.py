from pathlib import Path

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
def create_folders(out_dir, malware, pcaps, reports):
    Path(out_dir+malware).mkdir(parents=True, exist_ok=True)
    Path(out_dir+pcaps).mkdir(parents=True, exist_ok=True)
    Path(out_dir+reports).mkdir(parents=True, exist_ok=True)

