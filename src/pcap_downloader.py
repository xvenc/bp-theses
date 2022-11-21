from requests import Session
from os import path, walk
from pathlib import Path
from src.general import bcolors, check_dir
from src.report import create_report, create_file, check_downloaded
import time
import csv

class Downloader:

    def __init__(self, url : str, auth_token : str, client):
        self.url = url
        self.token = auth_token
        self.client = client

    def _download_pcap(self, sample_id, taksk_id, output_dir, filename):
        s = Session()
        headers = {'Authorization': 'Bearer {0}'.format(self.token)}
        data = s.get(url= self.url + f"{sample_id}/{taksk_id}/dump.pcap",headers=headers).content
        if output_dir[-1] != '/':
            output_dir += '/'
        if not path.isdir(output_dir):
            Path(output_dir).mkdir(parents=True, exist_ok=True)
        with open("%s/%s.pcap" % (output_dir,path.splitext(filename)[0]), "wb") as wf:
                    wf.write(data)
        return True

    def _report(self,sample_id, report_dir, report_file):
        try:
            report = self.client.overview_report(sample_id)
        except:
            print(bcolors.FAIL + "Couldnt download report." + bcolors.ENDC)
            return

        create_report(report, report_file, report_dir)

    def download_from_report(self, data, outpud_dir, filename):
        try:
            res = self._download_pcap(data['sample']['id'], "behavioral1",
                                      outpud_dir, filename)
        except:
            print(bcolors.FAIL + "ERROR: Couldnt download pcap files")
            exit(1)
        if res:
            print(bcolors.OKGREEN + "Downloaded pcap for " + 
            bcolors.OKBLUE+ "{0}".format(filename) + bcolors.ENDC)

    def download_from_csv(self, csv, task_id, outpud_dir):
        for row in csv:
            try:
                res = self._download_pcap(row['Sample_id'], task_id, 
                                        outpud_dir, row['Filename'])
            except:
                print(bcolors.FAIL + "ERROR: Couldnt download pcap files")
                exit(1)
            if res:
                print(bcolors.OKGREEN + "Downloaded pcap for " + 
                bcolors.OKBLUE+ "{0}".format(row['Filename']) + bcolors.ENDC)

    def download_sample(self, sample_id, task_id, outpud_dir, filename):
        res  = self._download_pcap(sample_id, task_id, outpud_dir, filename)
        if res:
            print(bcolors.OKGREEN + "Downloaded pcap for " + bcolors.OKBLUE + 
                    "{0}".format(filename) + bcolors.ENDC)

    # function to wait for the analysis to be done and then download the pcap
    def _download_wait(self, sample_id, filename, pcap_dir, subdir, report_dir):
        while True:
            try:
                status = self.client.sample_by_id(sample_id)['status']
            except:
                print(bcolors.FAIL + "Couldnt download pcap." + bcolors.ENDC)
                break;

            # check if analysis finished
            if  status == 'reported':
                self.download_sample(sample_id, 'behavioral1', pcap_dir+
                                        subdir, filename)

                report_f = create_file(path.splitext(filename)[0])
                self._report(sample_id, report_dir+subdir, report_f)
                break;

            else:
                time.sleep(60)

    def download_samples_for_directory(self, directory, family, family_dict, 
                                            report_dir, log_dir, pcap_dir):
        malware_dir = check_dir(directory)
        for subdir, dirs, files in walk(malware_dir+family):
            # check if directory contain files, not only other directories
            if files == []:
                continue
            print(bcolors.HEADER + "Downloading pcap files for directory: " +
                    bcolors.OKBLUE + f"{subdir}" + bcolors.ENDC)

            with open(log_dir+family_dict[family.lower()],mode='r') as csv_file:
                content = csv.DictReader(csv_file)
                for row in content:
                    f = path.join(subdir, row['Filename'])
                    # checking if it is a file and wasnt already downloaded
                    if path.isfile(f) and not check_downloaded(report_dir+subdir, f):
                        self._download_wait(row['Sample_id'], row['Filename'],
                                                    pcap_dir, subdir, report_dir)
