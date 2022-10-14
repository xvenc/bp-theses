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
    print(bcolors.OKCYAN+"  --submit options:"+bcolors.ENDC)
    print("\t-d\tSpecifies directory with malware samples.")
    print("\t-f\tSpecifies one malware sample.")
    print("\t-p\tSets password for zip/tar protected files.")
    print('\t-o\tSpecifies output directory name for dowloaded pcaps')
    print(bcolors.OKBLUE+"\n  --download"+bcolors.ENDC+"\tDownload all files from specified .csv file")
    print(bcolors.OKCYAN+"  --download options:"+bcolors.ENDC)
    print("\t-f\tSpecifies one .csv file with informations about samples.")
    print('\t-o\tSpecifies output directory name for dowloaded pcaps')
    print(bcolors.OKBLUE+"\n  --get"+bcolors.ENDC+"\tDownloads n malware samples of specified family")
    print(bcolors.OKCYAN+"  --get options:"+bcolors.ENDC)
    print("\t-m\tSpecifies malware family.")
    print("\t-l\tSpecifies how many samples of given family we want.")
    print('\t-o\tSpecifies output directory name for dowloaded samples')
    print(bcolors.OKBLUE+"\n  --all"+bcolors.ENDC+"\tDownloads n malware samples of specified family and runs analysis and than stores the pcap files")
    print(bcolors.OKCYAN+"  --all options:"+bcolors.ENDC)
    print("\t-m\tSpecifies malware family.")
    print("\t-l\tSpecifies how many samples of given family we want.")
    print('\t-d\tSpecifies output directory name for dowloaded pcaps')
    print("\t-o\tSpecifies output directory for malware samples.")
    print("Log files are automaticaly created. The file name is based on the input directory")


