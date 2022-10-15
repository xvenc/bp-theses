from requests import Session
from os import path
from pathlib import Path
from general import bcolors

class Downloader:

    def __init__(self, url : str, auth_token : str):
        self.url = url
        self.token = auth_token
    
    # TODO do it safely and return falsi if fail
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

    def download_from_csv(self, csv, task_id, outpud_dir):
        for row in csv:
            try:
                res = self._download_pcap(row['Sample_id'], task_id, outpud_dir, row['Filename'])
            except:
                print(bcolors.FAIL + "ERROR: Couldnt download pcap files")
                exit(1)
            if res:
                print(bcolors.OKGREEN + "Downloaded pcap for " + bcolors.OKBLUE+ "{0}".format(row['Filename']) + bcolors.ENDC)

    def download_sample(self, sample_id, task_id, outpud_dir, filename):
        res  = self._download_pcap(sample_id, task_id, outpud_dir, filename)
        if res:
            print(bcolors.OKGREEN + "Downloaded pcap for " + bcolors.OKBLUE + "{0}".format(filename) + bcolors.ENDC)
