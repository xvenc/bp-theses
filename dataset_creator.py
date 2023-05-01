"""
dataset_creator.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Main modul for creating the final dataset. 
"""

from src.suricata_flows import SuricataParser
from src.flow_reader import FlowReader
import getopt
import sys
from os import path

def help_msg():
    print("Usage: python3 dataset_creator.py [COMMAND]\n")
    print("Command:") 
    print("\t--help\tShow this help message.")
    print("\t-d\tPath to the folder with all reports from malware analysis obtained with triage_client.py.")
    print('\t-f\tPath to log file with Suricata flow records')
    print('\t-o\tPath to output folder. Folder needs to exist')

def argparse():
    """
    Function to parse command line arguments
    """
    arguments = {'-d' : [False, ""], '-f' : [False, ""], \
                '-o' : [False, ""]}

    try:
        options, args = getopt.getopt(sys.argv[1:], "d:f:o:", ["help"])
    except:
        help_msg()    
        sys.exit(1)

    for opt, arg in options:
        if opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt in arguments:
            arguments[opt][0] = True
            arguments[opt][1] = arg
    if not arguments['-d'][0] or not arguments['-f'][0]:
        help_msg()
        sys.exit(1)

    return arguments

if __name__ == "__main__":
    arg = argparse()
    flow_reader = FlowReader()
    suricata = SuricataParser()
    flow_reader.read_common_domains("common.txt")
    flow_reader.proccess_flows(arg['-d'][1], "malware")
    suricata.proccess_flows(arg['-f'][1])
    flow_reader.write_to_file(path.join(arg['-o'][1], 'dataset.csv'))
    suricata.write_to_file(path.join(arg["-o"][1], 'dataset2.csv'))