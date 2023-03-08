import json
from os import walk, path

class Flow:

    def __init__(self, src_ip, dst_ip, dst_p, app_prot, duration, flow, label):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_p
        self.proto = flow['proto'] 
        self.app_proto = app_prot
        self.duration = duration
        self.rx_bytes = flow['rx_bytes'] # Received bytes (without ethernet header)
        self.rx_packets = flow['rx_packets']
        self.tx_bytes = flow['tx_bytes'] # Transmitted bytes (without ethernet header)
        self.tx_packets = flow['tx_bytes']
        self.label = label # Normal or malicious
        # mby add domain but discuss this
        self.domain = "" 

    def __str__(self) -> str:
        return self.app_proto + " " + str(self.duration) + " " + str(self.rx_bytes) + " " +  str(self.rx_packets) + " " + str(self.tx_bytes) + " " + str(self.tx_packets) + " " + self.label

class FlowReader:

    def __init__(self):
        # The key to the dict is composed of 5 features
        # Src and dst IP, src and dst port and protocol
        self.flows = dict() # Dictionary for flows and it's features

    def _family_name(self, root, out_dir):
        return root.replace(out_dir, "")

    def _create_tuple(self, flow):
        flow['src'], src_p = flow['src'].split(":", 1)
        flow['dst'], dst_p = flow['dst'].split(":", 1)
        # TODO discuss this
        #return (flow['src'], flow['dst'], src_p, dst_p ,flow['proto'])
        #return (flow['dst'], dst_p ,flow['proto'])
        return (flow['src'], flow['dst'], dst_p ,flow['proto'])

    def _extract_flow(self, report, label):
        if 'flows' not in report:
            return

        for flow in report['flows']:
            index = self._create_tuple(flow)            
            if not self._create_flow(index, flow, label):
                # Flow alredy exist so increase the numbers
                self._add_flow()
            
    def _get_duration(self, flow):
        if 'last_seen' in flow or 'first_seen' in flow:
            return flow['last_seen'] - flow['first_seen']
        return -1

    # TODO ukladat domeny
    def _get_app_protocol(self, flow):
        if 'protocols' not in flow:
            return ""
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

    def _add_flow(self):
        pass

    def _create_flow(self, index, flow, label):
        if index in self.flows.keys():
            return False

        duration = self._get_duration(flow) 
        app_proto = self._get_app_protocol(flow)
        if app_proto == "dns":
            self.flows[index] = Flow(index[0], index[1], index[2], app_proto, duration, flow, "Normal")
        else:
            self.flows[index] = Flow(index[0], index[1], index[2], app_proto, duration, flow, label)

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
                        self._extract_flow(report['network'], label)

    def print_flows(self):
        for key, items in self.flows.items():
            print(key, "\t", items)

if __name__ == "__main__":
    flow_reader = FlowReader()
    flow_reader.proccess_flows("out/network", "malware")
    #flow_reader.print_flows() 