import getopt
import sys
import time
import signal
import os
from classifier import Classifier
from extractor import Extractor

suricata_log = "test_tmp/"

# Function to parse command line arguments
def argparse():

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
    classifier.score()
    sys.exit(0)

# MAIN
args, cmds = argparse()
extractor = Extractor()
extractor.extract(args, args['-t'][1]) # Extract ioc's from the report files
classifier = Classifier(extractor.ioc_map, extractor.ioc_cnt)
signal.signal(signal.SIGINT, handler)

classifier.init_counter() # Init counters for each family

# TODO live capture and score board
# If in common.txt than 1 point, if in infected than 5 points, other 2 points
while True and cmds['--live']:
    # Classify flows, http, dns and tls
    # classifier.classify(os.path.join(suricata_log, "eve-nsm.json"))
    # classifier.classify(os.path.join(suricata_log, "eve-flow.json"))
    classifier.live_capture(os.path.join(suricata_log, "eve-nsm.json"))
    # TODO print found IOC's and mby clear the read file

    time.sleep(4)

# Print statistics about families and found IOC's
if args['-m'][0]:
    extractor.ioc_spec_print(args['-m'][1], True)
elif args['-t'][0]:
    extractor.only_iocs()
else:
    extractor.ioc_print()
