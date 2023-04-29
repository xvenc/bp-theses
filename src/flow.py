"""
flow.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Modul with definition of class for representing important informations extracted from flows
"""

class Flow:
    """
    Class to containt all necessary informations about individual flows
    """

    def __init__(self, src_ip, dst_ip, dst_p, proto, app_prot, duration, rx_bytes,
                rx_packets, tx_bytes, tx_packets, label, family):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = int(dst_p)
        self.proto = str(proto).lower()
        self.app_proto = str(app_prot).lower()
        self.duration = int(duration)
        self.rx_bytes = int(rx_bytes) # Received bytes (without ethernet header)
        self.rx_packets = int(rx_packets)
        self.tx_bytes = int(tx_bytes) # Transmitted bytes (without ethernet header)
        self.tx_packets = int(tx_packets)
        self.label = label.lower() # Normal or malicious
        # mby add domain but discuss this
        #self.domain = "" 
        self.family = family 

    def __str__(self) -> str:
        return self.app_proto + " " + str(self.duration) + " " + str(self.rx_bytes) + " " +  str(self.rx_packets) + " " + str(self.tx_bytes) + " " + str(self.tx_packets) + " " + self.label + " " + self.family

