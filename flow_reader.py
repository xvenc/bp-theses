import json
from os import walk, path
from datetime import datetime
import csv

class Flow:

    def __init__(self, src_ip, dst_ip, dst_p, proto, app_prot, duration, rx_bytes,
                rx_packets, tx_bytes, tx_packets, label, family):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = int(dst_p)
        self.proto = str(proto)
        self.app_proto = str(app_prot)
        self.duration = int(duration)
        self.rx_bytes = int(rx_bytes) # Received bytes (without ethernet header)
        self.rx_packets = int(rx_packets)
        self.tx_bytes = int(tx_bytes) # Transmitted bytes (without ethernet header)
        self.tx_packets = int(tx_packets)
        self.label = label # Normal or malicious
        # mby add domain but discuss this
        #self.domain = "" 
        self.family = family 

    def __str__(self) -> str:
        return self.app_proto + " " + str(self.duration) + " " + str(self.rx_bytes) + " " +  str(self.rx_packets) + " " + str(self.tx_bytes) + " " + str(self.tx_packets) + " " + self.label + " " + self.family

class FlowReader:

    def __init__(self):
        # The key to the dict is composed of 5 features
        # Src and dst IP, src and dst port and protocol
        self.flows = dict() # Dictionary for flows and it's features
        self.domains = list() # List of 500 regular domains

    def _family_name(self, root, out_dir):
        return root.replace(out_dir, "")

    def _create_tuple(self, flow):
        flow['src'], src_p = flow['src'].split(":", 1)
        flow['dst'], dst_p = flow['dst'].split(":", 1)
        # TODO discuss this
        #return (flow['src'], flow['dst'], src_p, dst_p ,flow['proto'])
        #return (flow['dst'], dst_p ,flow['proto'])
        return (flow['src'], flow['dst'], dst_p ,flow['proto'])

    def _extract_flow(self, report, label, family):
        if 'flows' not in report:
            return

        for flow in report['flows']:
            index = self._create_tuple(flow)            
            if not self._create_flow(index, flow, label, family):
                # Flow alredy exist so increase the numbers
                self._increase_flow(self.flows[index], flow)
            
    def _get_duration(self, flow):
        if 'last_seen' in flow or 'first_seen' in flow:
            return flow['last_seen'] - flow['first_seen']
        return -1

    
    def _get_app_protocol(self, flow):
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

    # Get domain name from flow and remove potentional www. in the beggining
    def _get_domain(self, flow):
        if 'domain' in flow:
            return flow['domain'].replace('www.', '')
        
        return ""

    # Flow is already in the cache so increase all the features
    def _increase_flow(self, cache_flow, new_flow):
        duration = self._get_duration(new_flow)
        if duration != -1:
            cache_flow.duration += duration
        cache_flow.rx_bytes += new_flow['rx_bytes']
        cache_flow.rx_packets += new_flow['rx_packets']
        cache_flow.tx_bytes += new_flow['tx_bytes']
        cache_flow.tx_packets += new_flow['tx_packets']
        

    def _create_flow(self, index, flow, label, family):
        if index in self.flows.keys():
            return False

        duration = self._get_duration(flow) 
        app_proto = self._get_app_protocol(flow)
        domain = self._get_domain(flow)
        if domain in self.domains or app_proto == 'dns':
            label = "Normal"
        
        if label == "Normal":
            family = "-"
        
        self.flows[index] = Flow(index[0], index[1], index[2], flow['proto'],
                app_proto, duration, flow['rx_bytes'], flow['rx_packets'], 
                flow['tx_bytes'], flow['tx_packets'], label, family)

        return True

    def proccess_flows(self, directory, label):
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

    def create_row(self, key, items):
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
        row.append(items.tx_packets)
        row.append(items.tx_bytes)
        row.append(items.rx_bytes + items.tx_bytes)
        row.append(items.rx_packets + items.tx_packets)
        row.append(items.label)
        return row

    def write_to_file(self, path):
        header = ['Flow id', 'Src IP', 'Dst IP', 'Dst port', 'Protocol', 
        'Application protocol', 'Duration', 'Received bytes', 'Received packets',
        'Transmitted bytes', 'Transmitted packets', 'Total bytes', 'Total packets' 
        ,'label']
        with open(path, 'w') as csv_file:
            writer = csv.writer(csv_file)
            # Write header
            writer.writerow(header)
            for key, items in self.flows.items():
                row = self.create_row(key, items)
                writer.writerow(row)

    def read_common_domains(self, file):
        with open(file, "r") as f:
            data = f.readlines()
            self.domains = [l.strip() for l in data]
            # Remove potentional duplicants
            self.domains = list(dict.fromkeys(self.domains))

    def print_flows(self):
        for key, items in self.flows.items():
            print(key, "\t", items)

    
class SuricataParser:

    def __init__(self):
        self.flows = dict()

    def _create_tuple(self, flow):
        # Src IP, Dst IP, Dst port, protocol
        return (flow['src_ip'], flow['dest_ip'], flow['dest_port'], flow['proto'])

    def _extract_time(self, timestamp):
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        
    def _get_duration(self, start, end):
        start = self._extract_time(start)
        end = self._extract_time(end)
        start = int(str(start.minute * 60 + start.second) + str(start.microsecond)[:-3])
        end = int(str(end.minute * 60 + end.second) + str(end.microsecond)[:-3]) 
        return end - start

    def _create_flow_record(self, flow, index):
        if index in self.flows.keys():
            return False
        
        duration = self._get_duration(flow['flow']['start'], flow['flow']['end'])
        app_proto = "-"
        if 'app_proto' in flow:
            if flow['app_proto'] != 'failed':
                app_proto = flow['app_proto']

        self.flows[index] = Flow(index[0], index[1], index[2], flow['proto'],
                app_proto, duration, flow['flow']['bytes_toclient'], 
                flow['flow']['pkts_toclient'], flow['flow']['bytes_toserver'],
                flow['flow']['pkts_toserver'], "Normal", "-")

    def _update_flow(self, new_flow, index):
        cache_flow = self.flows[index]
        cache_flow.duration += self._get_duration(new_flow['start'], new_flow['end'])
        cache_flow.rx_bytes += new_flow['bytes_toclient']
        cache_flow.rx_packets += new_flow['pkts_toclient']
        cache_flow.tx_bytes += new_flow['bytes_toserver']
        cache_flow.tx_packets += new_flow['pkts_toserver']
        

    def _extract_features(self, flow):
        index = self._create_tuple(flow)
        if not self._create_flow_record(flow, index):
            # Flow is already in the cache
            self._update_flow(flow['flow'], index)


    def proccess_flows(self, file, label = "Normal"):
        for record in open(file, 'r'):
            flow = json.loads(record)
            self._extract_features(flow)

    def print_flows(self):
        print("\t\t\tKey\t\t\t app_proto duration rx_b rx_p tx_b tx_p label")
        for key, items in self.flows.items():
            print(key, "\t", items)


if __name__ == "__main__":
    flow_reader = FlowReader()
    suricata = SuricataParser()
    flow_reader.read_common_domains("common.txt")
    flow_reader.proccess_flows("out/network/", "malware")
    suricata.proccess_flows('test_tmp/eve-flow.json')
    flow_reader.write_to_file('dataset.csv')
    #flow_reader.print_flows()
    #suricata.print_flows()
