"""
sample_downloader.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Modul with definition of class to download malware samples of specified malware family
"""

import requests
from os import path
from pathlib import Path
from src.general import bcolors

class SampleDownloader:
    """
    Class to download malware samples from abuse.ch online malware database
    """

    def __init__(self, url='https://mb-api.abuse.ch/api/v1/'):
        self.url = url;

    def _store_sample(self, out_dir, family, res, hash256):
        """
        Store sample in specified directory with it's hash as name.
        If the directory doesn't exists it will be created.
        """
        if out_dir[-1] != '/':
            out_dir += '/'
        out_put = path.join(out_dir, family)
        if not path.isdir(out_put):
            Path(out_put).mkdir(parents=True, exist_ok=True)
        
        with open(path.join(out_put, hash256+'.zip'), 'wb') as wf:
            wf.write(res.content)

        print(bcolors.OKGREEN + "Downloaded malware sample: " + bcolors.OKBLUE + hash256+".zip" + bcolors.ENDC)

    def get_query(self, family, limit = 10):
        """
        Query limit number of malware samples for a specified family from the online database.
        """
        data = {
            'query': 'get_siginfo',
            'signature': ''+family+'',
            'limit' : limit
        }
        try:
            res = requests.post(self.url,data=data,timeout=120)
        except:
            print(bcolors.FAIL + "Error. HTTPS request timeouted.")
            return "", 1
        res_json = res.json()
        if res_json['query_status'] == 'ok':
            print(bcolors.OKCYAN + f"Queried {limit} samples for family " + bcolors.OKBLUE + family
                  + bcolors.OKCYAN + ". Now the samples will be downloaded."+ bcolors.ENDC)
        else:
            print(bcolors.FAIL + "Error while quering the samples. Ilegal signature")
            return "", 1
        return res_json, 0

    def download_samples(self, query_json, out_dir, family):
        """
        Download queried malware samples and store those samples in a directory. 
        """
        for sample in query_json['data']:
            data = {
                'query' : 'get_file',
                'sha256_hash' : sample['sha256_hash']
            }
            try:
                res = requests.post(self.url, data=data, timeout=120)
            except:
                print(bcolors.FAIL + "Error. HTTPS request timeouted.")
                return 1
            if res.status_code != 200:
                print(bcolors.FAIL + "Error. Couldnt download samples.")
                return 1
            self._store_sample(out_dir, family, res, sample['sha256_hash'])
        return 0