"""
capture.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Main modul for live or offline capture and classification of network traffic
"""

import getopt
import sys
import json
import signal
import os
import threading
from src.classifier import Classifier
from src.extractor import Extractor
from src.stats import Stats
from src.ml_classifier import MLClassifier
from machine_learning import load_dataset
from sklearn.ensemble import RandomForestClassifier

suricata_log = "/var/log/suricata/all.json"
normal_dataset = "dataset2.csv"
malware_dataset = "dataset.csv"


statistics = Stats()

# Function to parse command line arguments
def argparse():
    # -d for folder to extract from
    # -m for one specific malware sample
    # -t for found specific types of IOC's
    arguments = {'-d' : [False, ""], '-m' : [False, ""], \
                 '-t' : [False, None]}
    commands = {'--verbose' : False}

    try:
        options, args = getopt.getopt(sys.argv[1:], "d:m:t:", ["help", "verbose"])
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
        elif opt in commands:
            commands[opt] = True

    return arguments, commands

def handler(signum, frame):
    """
    Function to handle SIGINT and exit with 0 and print overall statistics
    """
    print("\n")
    statistics.score()
    sys.exit(0)

def tail(file_stream):
    """
    Function to read last entry from log file
    """
    file_stream.seek(0, os.SEEK_END)

    while True:
        if file_stream.closed:
            raise StopIteration

        line = file_stream.readline()
        yield line

def stats(statistics):
    """
    Function that is started separate thread and print statistics about proccessed log records
    """
    threading.Timer(30, stats, args=[statistics],).start()
    print("\nNormal flows: ",statistics.tmp_normal)
    print("Malicious flows: ", statistics.tmp_malware)
    print("All log recors: ", statistics.log_cnt)
    print("\n")
    statistics.reset()

def live_caputure(log_file, ioc_classifier, ml_classifier, cmds):
    """
    Function to read last record from file and proccess it
    """
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

        # If it's a flow predict if its a malicious one
        predicted = ml_classifier.predict(json_obj)

        if predicted == 1:
            statistics.increment_malware()
            if cmds['--verbose']:
                print(f"Malicious number {statistics.malware} with src IP: {json_obj['src_ip']}:{json_obj['src_port']} and dst IP: {json_obj['dest_ip']}:{json_obj['dest_port']}")
        elif predicted == 0:
            statistics.increment_normal()
            if cmds['--verbose']:
                print("Normal ", statistics.normal)
        
        if ioc in ioc_classifier.iocs:
            if cmds['--verbose']:
                print("Found ioc: ", ioc)
            statistics.add_ioc(ioc)
        
        if ip_match != None and predicted == 1:
            if cmds['--verbose']:
                print("Found IOC ip adress and flow was detected as malicious: ", ip_match, f"flow: {json_obj['src_ip']}:{json_obj['src_port']}->{json_obj['dest_ip']}:{json_obj['dest_port']}")
            statistics.add_ioc(ip_match)


# MAIN
if __name__ == "__main__":
    args, cmds = argparse()
    extractor = Extractor()
    extractor.read_common_domains("common.txt")
    extractor.read_common_ips("common_ips.txt")
    extractor.extract(args['-m'][0], args['-m'][1], args['-t'][1]) # Extract ioc's from the report files
    classifier = Classifier(extractor.ioc_map, extractor.ioc_cnt) # Classifier to classifi if DNS, TLS or HTTP containe IOC's
    ml_classifier = MLClassifier(RandomForestClassifier(n_estimators=50, max_depth=140, min_samples_leaf=1, min_samples_split=2, oob_score=False),
                                load_dataset(normal_dataset, malware_dataset))
    signal.signal(signal.SIGINT, handler) # Init a sig init handler

    classifier.init_counter() # Init counters for each family
    ml_classifier.train() # Train model

    # Live capture from Suricata log file
    print("\n\nLive capture started")
    live_caputure(suricata_log, classifier, ml_classifier, cmds)