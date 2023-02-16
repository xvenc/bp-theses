import json

class Classifier:

    matched = {}
    def __init__(self, ioc_map, ioc_cnt):
        self.iocs = ioc_map
        self.cnt = ioc_cnt

    def _score(self, match):
        families = set(val for val in self.iocs.values())
        for family in families:
            print(f"The score for family {family} is {round(match/self.cnt[family] * 100, 2)}%")
            print(f"{match} successful matches.")

    def classify(self, file):

        match = 0
        for record in open(file, 'r'):
            json_obj = json.loads(record)
            if json_obj['dns']['rrname'] in self.iocs and json_obj['dns']['rrname'] not in self.matched:
                self.matched[json_obj['dns']['rrname']] = self.iocs[json_obj['dns']['rrname']]
                match += 1

        self._score(match)

