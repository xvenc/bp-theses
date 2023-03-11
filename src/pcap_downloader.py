from requests import Session
from os import path, walk
from pathlib import Path
from src.general import bcolors, check_dir
from src.report import create_report, create_report_file, check_downloaded
import time
import csv

class Downloader:

    def __init__(self, url : str, auth_token : str, client):
        self.url = url
        self.token = auth_token
        self.client = client

    def _download_pcap(self, sample_id, taksk_id, output_dir, filename, num):
        s = Session()
        headers = {'Authorization': 'Bearer {0}'.format(self.token)}
        try:
            data = s.get(url= self.url + f"{sample_id}/{taksk_id}/dump.pcap",headers=headers).content
        except:
            print(bcolors.FAIL + "Couldnt download pcap." + bcolors.ENDC)
            return
        if output_dir[-1] != '/':
            output_dir += '/'
        if not path.isdir(output_dir):
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        to_open = path.join(output_dir, path.splitext(filename)[0]+f"_{num}.pcap")
        with open(to_open, "wb") as wf:
                    wf.write(data)
        return True

    # Function to download overview report of the analysis
    def _get_overview_report(self, sample_id, report_dir, report_file):
        try:
            report = self.client.overview_report(sample_id)
        except:
            print(bcolors.FAIL + "Couldnt download overview report." + bcolors.ENDC)
            return

        create_report(report, report_file, report_dir)

    def _get_network_report(self, sample_id, report_dir, report_file, report_type):
        try:
            # Get task report from behavioral1 analysis(windows7 analysis)
            net_report = self.client.task_report(sample_id, report_type)
        except:
            print(bcolors.FAIL + "Couldn't download task report." + bcolors.ENDC)
            return
        create_report(net_report, report_file, report_dir)

    def download_from_report(self, data, outpud_dir, filename):
        try:
            res = self._download_pcap(data['sample']['id'], "behavioral1",
                                      outpud_dir, filename, "1")
        except:
            print(bcolors.FAIL + "ERROR: Couldnt download pcap files")
            exit(1)
        if res:
            print(bcolors.OKGREEN + "Downloaded pcap for " + 
            bcolors.OKBLUE+ "{0}".format(filename) + bcolors.ENDC)

    def download_from_csv(self, csv, task_id, outpud_dir, num):
        for row in csv:
            try:
                res = self._download_pcap(row['Sample_id'], task_id, 
                                        outpud_dir, row['Filename'],
                                        num)
            except:
                print(bcolors.FAIL + "ERROR: Couldnt download pcap files")
                exit(1)
            if res:
                print(bcolors.OKGREEN + "Downloaded pcap for " + 
                bcolors.OKBLUE+ "{0}".format(row['Filename']) + bcolors.ENDC)

    def download_sample(self, sample_id, task_id, outpud_dir, filename, num):
        res  = self._download_pcap(sample_id, task_id, outpud_dir, filename, num)
        if res:
            print(bcolors.OKGREEN + "Downloaded pcap for " + bcolors.OKBLUE + 
                    "{0}".format(filename) + bcolors.ENDC)

    # function to wait for the analysis to be done and then download the pcap
    def _download_wait(self, sample_id, filename, pcap_dir, family, report_dir, network_dir):
        while True:
            try:
                status = self.client.sample_by_id(sample_id)['status']
            except:
                print(bcolors.FAIL + "Couldnt download pcap." + bcolors.ENDC)
                break;

            # check if analysis finished
            if  status == 'reported':
                # Download pcap files from both analysis
                self.download_sample(sample_id, 'behavioral1', path.join(pcap_dir, family),
                                     filename, "1")
                self.download_sample(sample_id, 'behavioral2', path.join(pcap_dir, family),
                                     filename, "2")

                self._get_overview_report(sample_id, path.join(report_dir, family), 
                create_report_file(path.splitext(filename)[0], ""))

                self._get_network_report(sample_id, path.join(network_dir, family), 
                create_report_file(path.splitext(filename)[0], "_1"), "behavioral1")

                self._get_network_report(sample_id, path.join(network_dir, family), 
                create_report_file(path.splitext(filename)[0], "_2"), "behavioral2")
                break;

            else:
                time.sleep(60)

    def download_samples_for_directory(self, directory, family, family_dict, 
                                            report_dir, log_dir, pcap_dir, network_dir):
        malware_dir = check_dir(directory)
        for root, dirs, files in walk(path.join(malware_dir, family)):
            # check if directory contain files, not only other directories
            if files == []:
                continue
            print(bcolors.HEADER + "Downloading pcap files for directory: " +
                    bcolors.OKBLUE + f"{root}" + bcolors.ENDC)

            with open(log_dir+family_dict[family.lower()],mode='r') as csv_file:
                content = csv.DictReader(csv_file)
                for row in content:
                    f = path.join(root, row['Filename'])
                    # checking if it is a file and wasnt already downloaded
                    if path.isfile(f) and not check_downloaded(path.join(report_dir, family), f):
                        self._download_wait(row['Sample_id'], row['Filename'],
                                                    pcap_dir, family, report_dir, network_dir)
