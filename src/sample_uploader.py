from src.general import bcolors
import time
from src.report import *
from os import walk, path

class Uploader:

    def __init__(self, report_dir, triage_client):
        self.report_dir = report_dir
        self.client = triage_client

    def _check_dir(self, directory):
        if directory[-1] != '/':
            directory += '/'
        return directory

    # function to wait for the analysis to be done and then download the pcap
    def _download_pcap(self, client, res, pcap_dir, subdir, d):
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

    def _report(self, client, res, report_dir, report_file):
        try:
            report = client.overview_report(res['id'])
        except:
            print(bcolors.FAIL + "Couldnt download report." + bcolors.ENDC)
            return

        create_report(report, report_file, report_dir)

    # function to submit all files from a directory
    def submit_directory(self, opt, client, d, cmd, family):
        malware_dir = self._check_dir(opt['-d'][1])
        pcap_dir = self._check_dir(opt['-o'][1])
        create_folder(self.report_dir)
        for subdir, dirs, files in walk(malware_dir+family):
            # check if directory contain files, not only other directories
            if files == []:
                continue
            print(bcolors.HEADER + "Submitting files from directory: " +bcolors.OKBLUE + f"{subdir}" + bcolors.ENDC)
            create_malware_folder(self.report_dir+subdir)

            # iterate trough files in malware directory
            for file in files:
                f = path.join(subdir, file)

                # checking if it is a file and wasnt already downloaded
                if path.isfile(f) and not check_downloaded(self.report_dir+subdir, f):
                    res = self.submit_file(f)
                    if res == "":
                        continue
                    print("Submitted malware: " + bcolors.OKBLUE + "{0}".format(res['filename']) + bcolors.ENDC)

                    report_f = create_file(path.splitext(res['filename'])[0])

                    # download pcap files after sumbiting
                    if cmd['--now']:
                        print("Downloading",end="")
                        self._download_pcap(client, res, pcap_dir, subdir, d)
                        self._report(client, res, self.report_dir+subdir, report_f)
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
