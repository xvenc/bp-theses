import json
import getopt
import sys
from os import walk, path

class Extractor:

    """
    dict: IOC's -> malware
    list: malware -> number of IOS's
    """
    ioc_map = {}

    def __init__(self, report_dir = "out/reports/"):
        self.dir = report_dir

    def _family_name(self, root):
        return root.replace(self.dir, "")

    def _get_iocs(self, report):
        if report['targets'] != None and 'iocs' in report['targets'][0]:
            return report['targets'][0]['iocs']

        return None

    def _inser(self, iocs, family):
        for key, vals in iocs.items():
            for val in vals:
                self.ioc_map[val] = family


    def extract(self):

        for root, dirs, files in walk(self.dir):
            family = self._family_name(root)
            if family == '':
                continue
            for filename in files:
                with open(path.join(root, filename)) as j_file:
                    report = json.load(j_file)
                    print(self._get_iocs(report))
                    iocs = self._get_iocs(report)
                    self._inser(iocs, family)
                    break
            break
                    
    def ioc_print(self):
        for key, val in self.ioc_map.items():
            print(key, " ", val)

def argparse():

    arguments = {'-d' : [False, ""]}

    try:
        options, args = getopt.getopt(sys.argv[1:], "d:", ["help"])
    except:
    #    help()
        print("Error")
        sys.exit(1)

    for opt, arg in options:
        if opt == "--help":
            print("HELP")
            sys.exit(0)
        elif opt in arguments:
            arguments[opt][0] = True
            arguments[opt][1] = arg

# MAIN
argparse()
extractor = Extractor()
extractor.extract()
extractor.ioc_print()