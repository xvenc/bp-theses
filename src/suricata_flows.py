"""
suricata_flows.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Modul with definition of class for extracting flows from Suricata log file and creating hash table with them
"""

import json
import csv
from datetime import datetime
from src.flow import Flow

class SuricataParser:
    """
    Class to read flows from Suricata log files and store them into a dictionary. 
    """
    # Variables to keep track about updated and created flows
    update = 0
    create = 0

    def __init__(self):
        self.flows = dict()

    def _create_tuple(self, flow):
        """
        Create a tuple which is an index into the dictionary.
        The index contains src and dst IP, src and dst port and transport protocol
        """
        return (flow['src_ip'], flow['dest_ip'],flow['src_port']  ,flow['dest_port'], flow['proto'])

    def extract_time(self, timestamp):
        """
        Convert timestamp from string to date time for easier manipulation
        """
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        
    def get_duration(self, start, end):
        """
        Get duration of the flow. If there is not enough informations return -1.
        """
        start = self.extract_time(start)
        end = self.extract_time(end)
        duration = str(end-start)
        if duration == "0:00:00":
            return 0
        sec = str(int(duration.split(":")[1]) * 60 + int(duration.split(':')[2].split('.')[0]))
        milisec = duration.split('.')[1][:3]
        time = int(sec + milisec)
        return time 

    def _create_flow_record(self, flow, index):
        """
        Flow doesn't exists in the cache so create new entry with 
        all important informations
        """
        duration = self.get_duration(flow['flow']['start'], flow['flow']['end'])
        app_proto = "-"
        if 'app_proto' in flow:
            if flow['app_proto'] != 'failed':
                app_proto = flow['app_proto']

        self.flows[index] = Flow(flow['src_ip'], flow['dest_ip'], flow['dest_port'], flow['proto'],
                app_proto, duration, flow['flow']['bytes_toclient'], 
                flow['flow']['pkts_toclient'], flow['flow']['bytes_toserver'],
                flow['flow']['pkts_toserver'], "Normal", "-")

    def _update_flow(self, new_flow, index):
        """
        Flow is already in the cache so increase all the features
        """
        cache_flow = self.flows[index]
        cache_flow.duration += self.get_duration(new_flow['start'], new_flow['end'])
        cache_flow.rx_bytes += new_flow['bytes_toclient']
        cache_flow.rx_packets += new_flow['pkts_toclient']
        cache_flow.tx_bytes += new_flow['bytes_toserver']
        cache_flow.tx_packets += new_flow['pkts_toserver']
        

    def _extract_features(self, flow):
        """
        Decide if the flow alredy is in the cache so update the values or  
        create new flow record in the cache
        """
        index = self._create_tuple(flow)
        if index in self.flows.keys():
            # Flow is already in the cache
            self._update_flow(flow['flow'], index)
            self.update += 1
        else:
            self._create_flow_record(flow, index)
            self.create += 1


    def proccess_flows(self, file, label = "Normal"):
        """
        Main function to iterate through the flow records in one file and create flows
        """
        for record in open(file, 'r'):
            flow = json.loads(record)
            if flow['proto'] in ['UDP', 'TCP']:
                self._extract_features(flow)
        #print("Normal flows") 
        #print("Updated: ", self.update)
        #print("Created: ", self.create)

    def print_flows(self):
        print("\t\t\tKey\t\t\t app_proto duration rx_b rx_p tx_b tx_p label")
        for key, items in self.flows.items():
            print(key, "\t", items)

    def create_row(self, key, items):
        """
        Create a row into a csv file with all the information from the flow.
        """
        row = []
        row.append(hash(key))
        row.append(items.src_ip)
        row.append(items.dst_ip)
        row.append(items.dst_port)
        row.append(items.proto)
        row.append(items.app_proto)
        row.append(items.duration)
        row.append(items.rx_bytes)
        row.append(items.rx_packets)
        row.append(items.tx_bytes)
        row.append(items.tx_packets)
        row.append(items.rx_bytes + items.tx_bytes)
        row.append(items.rx_packets + items.tx_packets)
        row.append(items.label)
        row.append(items.family)
        return row

    def write_to_file(self, path):
        """
        Write all flows and informations into a csv file.
        """
        header = ['Flow id', 'Src IP', 'Dst IP', 'Dst port', 'Protocol', 
        'Application protocol', 'Duration', 'Received bytes', 'Received packets',
        'Transmitted bytes', 'Transmitted packets', 'Total bytes', 'Total packets' 
        ,'label', 'family']
        with open(path, 'w') as csv_file:
            writer = csv.writer(csv_file)
            # Write header
            writer.writerow(header)
            for key, items in self.flows.items():
                row = self.create_row(key, items)
                writer.writerow(row)

