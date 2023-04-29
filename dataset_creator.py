"""
dataset_creator.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Main modul for creating the final dataset. 
"""

from src.suricata_flows import SuricataParser
from src.flow_reader import FlowReader

if __name__ == "__main__":
    flow_reader = FlowReader()
    suricata = SuricataParser()
    flow_reader.read_common_domains("common.txt")
    flow_reader.proccess_flows("out/network/", "malware")
    suricata.proccess_flows('test_tmp/eve-flow.json')
    flow_reader.write_to_file('dataset.csv')
    suricata.write_to_file('dataset2.csv')
