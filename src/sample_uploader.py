from src.general import bcolors
from src.report import *
from os import walk, path
from src.csv_writer import check_recorded, create_file_name, write_header, log

class Uploader:

    def __init__(self, report_dir, triage_client, log_dir):
        self.report_dir = report_dir
        self.client = triage_client
        self.logs = log_dir

    def _check_dir(self, directory):
        if directory[-1] != '/':
            directory += '/'
        return directory

    # function to submit all files from a directory
    def submit_directory(self, opt, client, family):
        malware_dir = self._check_dir(opt['-d'][1])
        create_folder(self.report_dir)
        create_folder(self.logs)

        # iterate through all directories and sub  directories
        for subdir, dirs, files in walk(malware_dir+family):
            # check if directory contain files, not only other directories
            if files == []:
                continue
            print(bcolors.HEADER + "Submitting files from directory: " +
                bcolors.OKBLUE + f"{subdir}" + bcolors.ENDC)
            # create csv log file
            log_f = create_file_name(subdir)
            write_header(log_f, self.logs)
            # create folder for reports
            create_malware_folder(self.report_dir+subdir)

            # iterate trough files in malware directory
            for file in files:
                f = path.join(subdir, file)

                # checking if it is a file and wasnt already downloaded
                if path.isfile(f) and not check_downloaded(self.report_dir+subdir, f):
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
