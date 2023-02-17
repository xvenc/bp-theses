import json
import getopt
import sys
from os import walk, path
from classifier import Classifier

class Extractor:

    """
    dict: IOC's -> malware
    list: malware -> number of IOS's
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

    def _inser(self, iocs, family, cnt):
        for key, vals in iocs.items():
            for val in vals:
                self.ioc_map[val] = family
                cnt += 1
        return cnt

    def extract(self, args):

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
                            cnt = self._inser(iocs, family, cnt)

            self.ioc_cnt[family] = cnt

    def ioc_print(self):
        for key, val in self.ioc_cnt.items():
            print(f"Family {key} - {val} indicators")

    def ioc_spec_print(self, sample, key_yes):
        i = 0
        for key, val in self.ioc_map.items():
            if i == 0:
                print(f"IOC's for family {val} and sample {sample} - {self.ioc_cnt[val]} IOC's.")
                i += 1
            if key_yes:
                print(key)

def argparse():

    arguments = {'-d' : [False, ""], '-m' : [False, ""]}
    try:
        options, args = getopt.getopt(sys.argv[1:], "d:m:", ["help"])
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

    return arguments

# MAIN
args = argparse()
extractor = Extractor()
classifier = Classifier(extractor.ioc_map, extractor.ioc_cnt)

extractor.extract(args)
classifier.classify("test_tmp/eve-nsm.json")
classifier.classify("test_tmp/eve-ips.json")
classifier.score()

#if args['-m'][0]:
#    extractor.ioc_spec_print(args['-m'][1], True)
#else:
#    extractor.ioc_print()
