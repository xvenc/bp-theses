"""
flow_reader.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Modul with definition of class for extracting malware flows from triage report file and creating hash table with them
"""

import json
from os import walk, path
from flow import Flow
import csv

class FlowReader:
    """
    Class to read flows from sandbox report files and store them into a dictionary. 
    """
    update = 0
    create = 0

    def __init__(self):
        # The key to the dict is composed of 5 features
        # Src and dst IP, src and dst port and protocol
        self.flows = dict() # Dictionary for flows and it's features
        self.domains = list() # List of 500 regular domains

    def _family_name(self, root, out_dir):
        """
        Return family name from an absolute directory name
        """
        return root.replace(out_dir, "")

    def _create_tuple(self, flow):
        """
        Create a tuple which is an index into the dictionary.
        The index contains src and dst IP, src and dst port and transport protocol
        """
        src_ip, src_p = flow['src'].split(":", 1)
        dst_ip, dst_p = flow['dst'].split(":", 1)
        return (src_ip, dst_ip, src_p, dst_p ,flow['proto'])

       
    def _get_duration(self, flow):
        """
        Get duration of the flow. If there is not enough informations return -1.
        """
        if 'last_seen' in flow or 'first_seen' in flow:
            return flow['last_seen'] - flow['first_seen']
        return -1

    
    def _get_app_protocol(self, flow):
        """
        Get what application protocol was the flow using and return it.
        If none then return "-".
        """
        if 'protocols' not in flow:
            return "-"
        else:
            protocols = flow['protocols']
        if len(protocols) == 1:
            if protocols[0] == "dns":
                return "dns"
            elif protocols[0] == "http":
                return "http"
            elif protocols[0] == "https":
                return "https"
            elif protocols[0] == "tls":
                return "tls"
        
        elif len(protocols) == 2:
            if protocols[1] == "http":
                return "http"
            elif protocols[1] == "https":
                return "https"
        
        return "-"

    def _get_domain(self, flow):
        """
        Get domain name from flow and remove potentional www. in the beggining
        """
        if 'domain' in flow:
            return flow['domain'].replace('www.', '')
        
        return ""

    def _increase_flow(self, cache_flow, new_flow):
        """
        Flow is already in the cache so increase all the features
        """
        duration = self._get_duration(new_flow)
        if duration != -1:
            cache_flow.duration += duration
        cache_flow.rx_bytes += new_flow['rx_bytes']
        cache_flow.rx_packets += new_flow['rx_packets']
        cache_flow.tx_bytes += new_flow['tx_bytes']
        cache_flow.tx_packets += new_flow['tx_packets']
        

    def _create_flow(self, index, flow, label, family):
        """
        Flow doesn't exists in the cache so create new entry with 
        all important informations
        """
        duration = self._get_duration(flow) 
        app_proto = self._get_app_protocol(flow)
        domain = self._get_domain(flow)
        dst_port = 0
        if len(flow['dst'].split(':',1)) > 1:
            dst_port = flow['dst'].split(':',1)[1]

        if domain in self.domains or app_proto == 'dns':
            label = "Normal"
        
        if label == "Normal":
            family = "-"
         
        self.flows[index] = Flow(flow['src'].split(':',1)[0], flow['dst'].split(':',1)[0], 
                dst_port, flow['proto'],
                app_proto, duration, flow['rx_bytes'], flow['rx_packets'], 
                flow['tx_bytes'], flow['tx_packets'], label, family)

        return True

    def _extract_flow(self, report, label, family):
        """
        Extract all flows from the dynamic report and create or increase 
        flows in the cache
        """
        if 'flows' not in report:
            return

        for flow in report['flows']:
            index = self._create_tuple(flow)            
            if index in self.flows.keys():
                # Flow alredy exist so increase the numbers
                self._increase_flow(self.flows[index], flow)
                self.update += 1
            else:
                self._create_flow(index, flow, label, family)
                self.create += 1
                

    def proccess_flows(self, directory, label):
        """
        Main function to iterate through report directory and extract flows 
        from all report files
        """
        for root, dirs, files in walk(directory):
            family = self._family_name(root, directory)
            if family == "":
                continue
            for filename in files:
                with open(path.join(root, filename)) as j_file:
                    report = json.load(j_file)
                    if report['network']:
                        #print(root+"/"+filename)
                        self._extract_flow(report['network'], label, family)

        print("Updated: ", self.update)
        print("Created: ", self.create)

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

    def read_common_domains(self, file):
        """
        Read all the not malicious domain names from a text file and store them into a list
        """
        with open(file, "r") as f:
            data = f.readlines()
            self.domains = [l.strip() for l in data]
            # Remove potentional duplicants
            self.domains = list(dict.fromkeys(self.domains))

    def print_flows(self):
        for key, items in self.flows.items():
            print(key, "\t", items)