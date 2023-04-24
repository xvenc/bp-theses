import getopt
import sys
import json
import signal
import os
import threading
from classifier import Classifier
from extractor import Extractor
from ml_classifier import MLClassifier
from machine_learning import load_dataset
from sklearn.ensemble import RandomForestClassifier

suricata_log = "/var/log/suricata/all.json"
normal_dataset = "dataset2.csv"
malware_dataset = "dataset.csv"


class Stats:

    log_cnt = 0
    malware = 0
    normal = 0
    tmp_malware = 0
    tmp_normal = 0
    
    def __init__(self):
        pass

    def inc_log_cnt(self):
        self.log_cnt += 1

    def increment_malware(self):
        self.tmp_malware += 1
        self.malware += 1

    def increment_normal(self):
        self.tmp_normal += 1
        self.normal += 1 

    def reset(self):
        self.tmp_malware = 0
        self.tmp_normal = 0

    def score(self):
        print("--------------------------------------")
        print("Percentage of normal flows: " round(self.normal/self.log_cnt)*100,2)
        print("Percentage of malware flows: " round(self.malware/self.log_cnt)*100,2)
        print("Number of IOC's: ")

statistics = Stats()

# Function to parse command line arguments
def argparse():
    # -d for folder to extract from
    # -m for one specific malware sample
    # -t for found specific types of IOC's
    arguments = {'-d' : [False, ""], '-m' : [False, ""], \
                 '-t' : [False, None]}
    commands = {'--live' : False}

    try:
        options, args = getopt.getopt(sys.argv[1:], "d:m:t:", ["help", "live"])
    except:
        # help()
        print("Error")
        sys.exit(1)

    for opt, arg in options:
        if opt == "--help":
            print("HELP")
            sys.exit(0)
        elif opt in arguments:
            arguments[opt][0] = True
            arguments[opt][1] = arg
            if arguments['-t'][0] and arguments['-t'][1] not in ['domains', 'ips', 'urls']:
                print(arg)
                print("Wrong argument option for argument -t")
                sys.exit(1)
        elif opt in commands:
            commands[opt] = True

    return arguments, commands

# Function to handle SIGINT and exit with 0 and print overall statistics
def handler(signum, frame):
    print("\n")
    statistics.score()
    sys.exit(0)

# Function to read last entry from log file
def tail(file_stream):
    file_stream.seek(0, os.SEEK_END)

    while True:
        if file_stream.closed:
            raise StopIteration

        line = file_stream.readline()
        yield line

def stats(statistics):
    threading.Timer(30, stats, args=[statistics],).start()
    # TODO add printing stats and warning
    print("Normal: ",statistics.tmp_normal)
    print("Malicious: ", statistics.tmp_malware)
    print("All: ", statistics.log_cnt)
    print("\n")
    statistics.reset()

def live_caputure(log_file, ioc_classifier, ml_classifier):
    found_ioc = []
    stats(statistics)
    for record in tail(open(log_file, 'r')):
        try:
            json_obj = json.loads(record)
            statistics.inc_log_cnt()
        except ValueError:
            # Possible corrupt json entry, so skip to the next one
            continue

        # Extract iocs and ips from suricata log
        ioc = ioc_classifier.extract(json_obj)
        ip_match = ioc_classifier.extract_ip(json_obj)

        if ip_match == "8.8.8.8":
            ip_match = None

        # If it's a flow predict if its a malicious one
        predicted = ml_classifier.predict(json_obj)

        if predicted == 1:
            statistics.increment_malware()
            print("Malicious ", statistics.malware)
        else:
            statistics.increment_normal()
            print("Normal ", statistics.normal)
        
        if ioc in ioc_classifier.iocs:
            print("Found ioc: ", ioc)
            found_ioc.append(ioc)
        
        if ip_match != None:

            print("Found ip: ", ip_match)
            found_ioc.append(ioc)

    res = [*set(found_ioc)]
    #print("Normal: ", )
    #print("Malicious: ", malicious)
    #print("All: ", log_cnt)
    #print("Found IOCS: ", res)

# MAIN
if __name__ == "__main__":
    args, cmds = argparse()
    extractor = Extractor()
    extractor.extract(args['-m'][0], args['-m'][1], args['-t'][1]) # Extract ioc's from the report files
    classifier = Classifier(extractor.ioc_map, extractor.ioc_cnt) # Classifier to classifi if DNS, TLS or HTTP containe IOC's
    ml_classifier = MLClassifier(RandomForestClassifier(n_estimators=50, max_depth=140, min_samples_leaf=1, min_samples_split=2, oob_score=False),
                                load_dataset(normal_dataset, malware_dataset))
    signal.signal(signal.SIGINT, handler) # Init a sig init handler

    classifier.init_counter() # Init counters for each family
    ml_classifier.train() # Train model

    i = 0
    while True and cmds['--live']:
        # Live capture from Suricata log file
        if i == 0:
            print("\n\nLive capture started\n\n")
            i += 1
        live_caputure(suricata_log, classifier, ml_classifier)

    # Print statistics about families and found IOC's
    if args['-m'][0]:
        extractor.ioc_spec_print(args['-m'][1], True)
    elif args['-t'][0]:
        extractor.only_iocs()
    else:
        extractor.ioc_print()
        #extractor.family_iocs("smokeloader")
