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


