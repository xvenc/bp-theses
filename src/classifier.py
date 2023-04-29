"""
classifier.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Modul with definition of class for extracting important information from Suricata flow records 
and for classifing if the information is malware IOC
"""

import json
import os

class Classifier:
    """
    Class for parsing suricata json log records and extracting from them IP, URL adresess and domain names.
    And classifing if any of these informations is in found malware IOC's.
    """

    ioc_match = {} # Dictionary with already matched IOC's
    match_cnt = {}
    log_cnt = 0 # Count of proccessed log records

    def __init__(self, ioc_map, ioc_cnt):
        self.iocs = ioc_map # Dictionary with extracted IOC by extractor.py, IOC is index to the dictionary
        self.cnt = ioc_cnt # Dictionary with all families and number of it's IOC's

    def score(self):
        """
        Prints score for every family that has atleas one IOC.
        Prints also how many IOC's was found for each family.
        """
        for family in set(val for val in self.cnt.keys()):
            print(f"The score for family {family} is {round(self.match_cnt[family]/self.cnt[family] * 100, 2)}%. With {self.match_cnt[family]} successful matches.")
        print(f"During live capture was proccessed {self.log_cnt} entries.")
        print(self.ioc_match)

    def init_counter(self):
        """
        Init counter for each family that has atleast one IOC.
        The counter increases each time IOC from that family is found.
        """
        for family in set(val for val in self.cnt.keys()):
            self.match_cnt[family] = 0

    def _extract_http(self, json_obj):
        """
        Extract url adress from HTTP and HTTPS Suricata record
        """
        http = 'http://' + json_obj['http']['hostname']
        if json_obj['http']['url']:
            return http + json_obj['http']['url']

    def _extract_dns(self, json_obj):
        """
        Extract domain name from Suricata DNS record and returns it if it is 
        in the malicious IOCs
        """
        if json_obj['dns']['type'] == 'query':
            return json_obj['dns']['rrname']
        elif json_obj['dns']['type'] == 'answer':
            if 'grouped' in json_obj['dns']:
                for key, vals in json_obj['dns']['grouped'].items():
                    for val in vals:
                        if val in self.iocs:
                            return val
        return None

    def extract(self, json_obj):
        """
        Try to extract IOC based on the Suricata record apllication protocol.
        """
        if json_obj['event_type'] == 'dns':
            return self._extract_dns(json_obj)

        elif json_obj['event_type'] == 'http':
            return self._extract_http(json_obj)

        elif json_obj['event_type'] == 'tls':
            return self.extract_ip(json_obj)
        else:
            return None

    def extract_ip(self, json_obj):
        """
        Extract IP adress and returns it if is in malicious IOC's
        """
        if json_obj['event_type'] in ['flow']:
            if json_obj['src_ip'] in self.iocs:
                return json_obj['src_ip']
            elif json_obj['dest_ip'] in self.iocs:
                return json_obj['dest_ip']

        return None

    def classify(self, file):
        """
        Open Suricata record file and try to find all the malicious IOC's.
        """
        for record in open(file, 'r'):
            json_obj = json.loads(record)
            self.log_cnt += 1
            ioc = self.extract(json_obj)
            ip_match = self.extract_ip(json_obj)
            if (ioc in self.iocs and ioc not in self.ioc_match) or \
                (ip_match != None and ip_match not in self.ioc_match):

                if ioc:
                    self.ioc_match[ioc] = self.iocs[ioc]
                    self._increment(ioc)
                elif ip_match:
                    self.ioc_match[ip_match] = self.iocs[ip_match]
                    self._increment(ip_match)

    def _tail(self, file_stream):
        """
        Live read of the last record from specified log file stream.
        """
        file_stream.seek(0, os.SEEK_END)

        while True:
            if file_stream.closed:
                raise StopIteration

            line = file_stream.readline()
            yield line

    def _increment(self, ioc):
        """
        Increament counter for each family that has specified malicious IOC.
        """
        for family in self.iocs[ioc]:
            self.match_cnt[family] += 1

    def live_capture(self, file):
        """
        Read last entry from log file and check if it contains any malicious IOC.
        """
        for record in self._tail(open(file, 'r')):
            try:
                json_obj = json.loads(record)
                self.log_cnt += 1
            except ValueError:
                # Possible corrupt json entry, so skip to the next one
                continue
            # Extract iocs and ips from suricata log
            ioc = self.extract(json_obj)
            ip_match = self.extract_ip(json_obj)

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
