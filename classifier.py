import json

class Classifier:

    ioc_match = {}
    match_cnt = {}

    def __init__(self, ioc_map, ioc_cnt):
        self.iocs = ioc_map
        self.cnt = ioc_cnt

    def score(self):
        families = set(val for val in self.iocs.values())
        for family in families:
            print(f"The score for family {family} is {round(self.match_cnt[family]/self.cnt[family] * 100, 2)}%. With {self.match_cnt[family]} successful matches.")
        print(self.ioc_match)

    def init_counter(self):
        for family in set(val for val in self.iocs.values()):
            self.match_cnt[family] = 0

    def _extract_http(self, json_obj):
        http = 'http://' + json_obj['http']['hostname']
        if json_obj['http']['url']:
            return http + json_obj['http']['url']

    def _extract(self, json_obj):
        if json_obj['event_type'] == 'dns':
            return json_obj['dns']['rrname']

        elif json_obj['event_type'] == 'http':
            return self._extract_http(json_obj)

        elif json_obj['event_type'] == 'tls':
            return self._extract_ip(json_obj)
        else:
            return None

    def _extract_ip(self, json_obj):
        if json_obj['event_type'] in ['flow', 'tls']:
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
            if ioc in self.iocs and ioc not in self.ioc_match or ip_match != None and ip_match not in self.ioc_match:
                if ioc:
                    self.ioc_match[ioc] = self.iocs[ioc]
                    self.match_cnt[self.iocs[ioc]] += 1
                else:
                    self.ioc_match[ip_match] = self.iocs[ip_match]
                    self.match_cnt[self.iocs[ip_match]] += 1

    # TODO Function for live capture of malicious activity
    def live_capture(self, file):
        for record in open(file, 'r'):
            pass

