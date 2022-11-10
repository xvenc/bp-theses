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
    print(bcolors.OKBLUE+"\n  --download"+bcolors.ENDC+"\tDownload all files from specified .csv file")
    print(bcolors.OKCYAN+"  Options for download:"+bcolors.ENDC)
    print("\t-d\tSpecifies one folder with report files. Folder mustn't contain other folders.")
    print('\t-o\tSpecifies output directory name for dowloaded pcaps')
    print(bcolors.OKBLUE+"\n  --get"+bcolors.ENDC+"\tDownloads n malware samples of specified family")
    print(bcolors.OKCYAN+"  "+bcolors.ENDC)
    print("\t-m\tSpecifies malware family.")
    print("\t-l\tSpecifies how many samples of given family we want.")
    print('\t-d\tSpecifies output directory name for dowloaded samples')
    print("\t--now\tImmediately after submit downloads pcap files.")
    print(bcolors.OKBLUE+"\n  --all"+bcolors.ENDC+"\tDownloads n malware samples of specified family and runs analysis and than stores the pcap files")
    print(bcolors.OKCYAN+"  Options for all:"+bcolors.ENDC)
    print("\t-m\tSpecifies malware family. Or .txt file with malware family names each on new line of the file")
    print("\t-l\tSpecifies how many samples of given family we want.")
    print('\t-o\tSpecifies output directory name for dowloaded pcaps')
    print("\t-d\tSpecifies output directory for malware samples.")
    print("\t--now\tImmediately after submit downloads pcap files.")
    print("Log files are automaticaly created. The file name is based on the input directory")


