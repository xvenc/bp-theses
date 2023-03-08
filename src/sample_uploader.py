from src.general import bcolors, create_folder
from src.report import *
from os import walk, path
from src.csv_writer import check_recorded, create_file_name, write_header, log

class Uploader:

    def __init__(self, triage_client, log_dir):
        self.client = triage_client
        self.logs = log_dir

    def _check_dir(self, directory):
        if directory[-1] != '/':
            directory += '/'
        return directory

    # function to submit all files from a directory
    def submit_directory(self, malware_dir, client, family, report_dir, network_dir):
        malware_dir = self._check_dir(malware_dir)
        create_folder(self.logs)

        # iterate through all directories and sub  directories
        for root, dirs, files in walk(path.join(malware_dir,family)):
            # check if directory contain files, not only other directories
            if files == []:
                continue
            print(bcolors.HEADER + "Submitting files from directory: " +
                bcolors.OKBLUE + f"{root}" + bcolors.ENDC)
            # create csv log file
            log_f = create_file_name(root)
            write_header(log_f, self.logs)

            # create folder for reports
            create_folder(path.join(report_dir, family))
            # create folder for network reports
            create_folder(path.join(network_dir, family))

            # iterate trough files in malware directory
            for file in files:
                f = path.join(root, file)

                # checking if it is a file and wasnt already downloaded
                if path.isfile(f) and not check_downloaded(path.join(report_dir, family), f):
                    res = self.submit_file(f)
                    if res == "":
                        continue
                    print("Submitted malware for analysis: " + bcolors.OKBLUE + 
                            "{0}".format(res['filename']) + bcolors.ENDC)

                    if not check_recorded(log_f, self.logs, f):
                        log(res['id'], file, log_f, client, self.logs) 
                else:
                    print(bcolors.OKBLUE + file + bcolors.ENDC + bcolors.BOLD + " was already downloaded")
        return

    # function to submit simple file using triage API
    def submit_file(self, filepath : str):
        filename = path.basename(filepath)
        response = ""
        if path.isfile(filepath):
            try:
                response = self.client.submit_sample_file(filename, open(filepath, 'rb'), False, None, 'infected')
            except:
                print(bcolors.FAIL + "Error: Couldnt sent http request")
        return response
