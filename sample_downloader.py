import requests
from os import path, mkdir
from pathlib import Path
from general import bcolors

class SampleDownloader:

    def __init__(self, url='https://mb-api.abuse.ch/api/v1/'):
        self.url = url;

    def _store_sample(self, out_dir, family, res, hash256):
        if out_dir[-1] != '/':
            out_dir += '/'
        if not path.isdir(out_dir+family):
            Path(out_dir+family).mkdir(parents=True, exist_ok=True)
        with open(out_dir+family+'/'+hash256+'.zip', 'wb') as wf:
            wf.write(res.content)

        print(bcolors.OKGREEN + "Downloaded malware sample for family: " + bcolors.OKBLUE + family + bcolors.ENDC)

    def get_query(self, family, limit = 10):
        data = {
            'query': 'get_siginfo',
            'signature': ''+family+'',
            'limit' : limit
        }
        try:
            res = requests.post(self.url,data=data,timeout=15)
        except:
            print(bcolors.FAIL + "Error. HTTPS request timeouted.")
            exit(1)
        res_json = res.json()
        if res_json['query_status'] == 'ok':
            print(bcolors.OKCYAN + f"Queried {limit} samples for family " + bcolors.OKBLUE + family + bcolors.ENDC)
        else:
            print(bcolors.FAIL + "Error while quering the samples. Ilegal signature")
            exit(1)
        return res_json
    def download_samples(self, query_json, out_dir, family):

        for sample in query_json['data']:
            data = {
                'query' : 'get_file',
                'sha256_hash' : sample['sha256_hash']
            }
            try:
                res = requests.post(self.url, data=data, timeout=15)
            except:
                print(bcolors.FAIL + "Error. HTTPS request timeouted.")
                exit(1)
            if res.status_code != 200:
                print(bcolors.FAIL + "Error. Couldnt download samples.")
                exit(1)
            self._store_sample(out_dir, family, res, sample['sha256_hash'])


