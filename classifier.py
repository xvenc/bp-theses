import json
import os

class Classifier:

    ioc_match = {}
    match_cnt = {}
    log_cnt = 0

    def __init__(self, ioc_map, ioc_cnt):
        self.iocs = ioc_map
        self.cnt = ioc_cnt

    def score(self):
        for family in set(val for val in self.cnt.keys()):
            print(f"The score for family {family} is {round(self.match_cnt[family]/self.cnt[family] * 100, 2)}%. With {self.match_cnt[family]} successful matches.")
        print(f"During live capture was proccessed {self.log_cnt} entries.")
        print(self.ioc_match)

    def init_counter(self):
        for family in set(val for val in self.cnt.keys()):
            self.match_cnt[family] = 0

    def _extract_http(self, json_obj):
        http = 'http://' + json_obj['http']['hostname']
        if json_obj['http']['url']:
            return http + json_obj['http']['url']

    def _extract_dns(self, json_obj):
        if json_obj['dns']['type'] == 'query':
            return json_obj['dns']['rrname']
        elif json_obj['dns']['type'] == 'answer':
            if 'grouped' in json_obj['dns']:
                for key, vals in json_obj['dns']['grouped'].items():
                    for val in vals:
                        if val in self.iocs:
                            return val
        return None

    def _extract(self, json_obj):
        if json_obj['event_type'] == 'dns':
            return self._extract_dns(json_obj)

        elif json_obj['event_type'] == 'http':
            return self._extract_http(json_obj)

        elif json_obj['event_type'] == 'tls':
            return self._extract_ip(json_obj)
        else:
            return None

    def _extract_ip(self, json_obj):
        if json_obj['event_type'] in ['flow']:
            if json_obj['src_ip'] in self.iocs:
                return json_obj['src_ip']
            elif json_obj['dest_ip'] in self.iocs:
                return json_obj['dest_ip']

        return None

    def classify(self, file):
        for record in open(file, 'r'):
            json_obj = json.loads(record)
            ioc = self._extract(json_obj)
            ip_match = self._extract_ip(json_obj)
            if (ioc in self.iocs and ioc not in self.ioc_match) or \
                (ip_match != None and ip_match not in self.ioc_match):

                if ioc:
                    self.ioc_match[ioc] = self.iocs[ioc]
                    self._increment(ioc)
                elif ip_match:
                    self.ioc_match[ip_match] = self.iocs[ip_match]
                    self._increment(ip_match)

    # Function to read last entry from log file
    def _tail(self, file_stream):
        file_stream.seek(0, os.SEEK_END)

        while True:
            if file_stream.closed:
                raise StopIteration

            line = file_stream.readline()
            yield line

    def _increment(self, ioc):
        for family in self.iocs[ioc]:
            self.match_cnt[family] += 1

    # Function used to read log latest record from file and to proccess these records 
    def live_capture(self, file):
        for record in self._tail(open(file, 'r')):
            try:
                json_obj = json.loads(record)
                self.log_cnt += 1
            except ValueError:
                # Possible corrupt json entry, so skip to the next one
                continue
            # Extract iocs and ips from suricata log
            ioc = self._extract(json_obj)
            ip_match = self._extract_ip(json_obj)

            # Check if any of extracted info from suricata is in our malicious IOCs
            # And if it wasn't already matched
            if (ioc in self.iocs and ioc not in self.ioc_match) or \
                (ip_match != None and ip_match not in self.ioc_match):

                if ioc:
                    self.ioc_match[ioc] = self.iocs[ioc]
                    self._increment(ioc)
                    print(f"Warning possible malicious activity was found. IOC: {ioc}")
                elif ip_match:
                    self.ioc_match[ip_match] = self.iocs[ip_match]
                    self._increment(ip_match)
                    print(f"Warning possible malicious activity was found. IP: {ip_match}")
