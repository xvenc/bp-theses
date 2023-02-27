import json
from os import walk, path

class Extractor:

    """
    dict: IOC's -> malware
    dict: malware_cnt -> number of IOS's
    """
    ioc_map = {} # dictionary to map ioc indicator to family
    ioc_cnt = {} # dictionary to map family to exact number of indicators

    def __init__(self, report_dir = "out/reports/"):
        self.dir = report_dir

    def _family_name(self, root):
        return root.replace(self.dir, "")

    def _get_iocs(self, report):
        if report['targets'] != None and 'iocs' in report['targets'][0]:
            return report['targets'][0]['iocs']
        return None

    def _inser(self, iocs, family, cnt, ioc_type):
        for key, vals in iocs.items():
            if not ioc_type or key == ioc_type:
                for val in vals:
                    if val not in self.ioc_map:
                        self.ioc_map[val] = []
                        self.ioc_map[val].append(family)
                        cnt += 1
                    elif family not in self.ioc_map[val]:
                        self.ioc_map[val].append(family)
                        cnt += 1
        return cnt

    def extract(self, args, ioc_type):
        for root, dirs, files in walk(self.dir):
            cnt = 0
            family = self._family_name(root)
            if family == "":
                continue
            for filename in files:
                if not args['-m'][0] or path.splitext(filename)[0] == args['-m'][1]:
                    with open(path.join(root, filename)) as j_file:
                        report = json.load(j_file)
                        iocs = self._get_iocs(report)
                        if iocs != None:
                            cnt = self._inser(iocs, family, cnt, ioc_type)
                            self.ioc_cnt[family] = cnt

    # Print overall statistics about extracted IOC's for each family
    def ioc_print(self):
        for key, val in self.ioc_cnt.items():
            print(f"Family {key} - {val} indicators")

    # Print IOC's for specific sample 
    def ioc_spec_print(self, sample, key_yes):
        i = 0
        for key, val in self.ioc_map.items():
            if i == 0:
                print(f"IOC's for family {val} and sample {sample} - {self.ioc_cnt[val]} IOC's.")
                i += 1
            if key_yes:
                print(key)

    # Print specific type of the IOC's eg. only IP's or domains, etc.
    def only_iocs(self):
        families = []
        for key, val in self.ioc_map.items():
            if val not in families:
                print(f"\nFamily {val}\n")
                families.append(val)
            print(key)

    # Print IOC's for specific family
    def family_iocs(self, family):
        for key, vals in self.ioc_map.items():
            for val in vals:
                if val == family:
                    print(key)


