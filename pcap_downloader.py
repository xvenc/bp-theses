from requests import Session
from os import path
from pathlib import Path


class Downloader:

    def __init__(self, url : str, auth_token : str):
        self.url = url
        self.token = auth_token

    def _download_pcap(self, sample_id, taksk_id, outpud_dir, filename):
        s = Session()
        headers = {'Authorization': 'Bearer {0}'.format(self.token)}
        data = s.get(url= self.url + f"{sample_id}/{taksk_id}/dump.pcap",headers=headers).content
        if not path.isdir(outpud_dir):
            Path(outpud_dir).mkdir(parents=True, exist_ok=True)
        with open("%s/%s.pcap" % (outpud_dir,path.splitext(filename)[0]), "wb") as wf:
                    wf.write(data)
        return True

    def download_from_csv(self, csv, task_id, outpud_dir):
        for row in csv:
            res = self._download_pcap(row['Sample_id'], task_id, outpud_dir, row['Filename'])
            if res:
                print("Pcap for {0} downloaded.".format(row['Filename']))

    def download_sample(self, sample_id, task_id, outpud_dir, filename):
        res  = self._download_pcap(sample_id, task_id, outpud_dir, filename)
        if res:
            print("Pcap for {0} downloaded.".format(filename))
