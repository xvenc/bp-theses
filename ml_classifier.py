"""
ml_classifier.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Modul with class definition for preparing data from captured flow and classifing the flow 
"""

import os
import pandas as pd
from machine_learning import data_preproccessing, split_data
from flow_reader import SuricataParser

suricata_log = "test_tmp/eve-flow.json"

def tail(file_stream):
    # Function to read last entry from log file
    file_stream.seek(0, os.SEEK_END)

    while True:
        if file_stream.closed:
            raise StopIteration

        line = file_stream.readline()
        yield line

class MLClassifier:
    """
    Machine learning classifier to classifie one flow captured from Suricata JSON log file.
    Preprocces the flow and predict if it's malicious or normal
    """

    def __init__(self, model, df) -> None:
        self.model = model # ML model
        self.df = df # dataset used for training the model

    def train(self):
        df = data_preproccessing(self.df)
        train_data, test_data, train_labels, test_labels = split_data(df)
        self.model.fit(train_data, train_labels) 


    def get_values(self, flow_record):
        sur_par = SuricataParser()
        duration = sur_par.get_duration(flow_record['flow']['start'], flow_record['flow']['end'])
        app_proto = "-"
        flow = {}
        if 'app_proto' in flow_record:
            if flow_record['app_proto'] != 'failed':
                if flow_record['app_proto'] in ["tls", "dns", 'http', 'https']:
                    app_proto = flow_record['app_proto'].lower()
                

        flow['Duration'] = duration
        flow['Protocol'] = flow_record['proto'].lower()
        flow['Application protocol'] = app_proto
        flow['Received bytes'] = flow_record['flow']['bytes_toclient']
        flow['Received packets'] = flow_record['flow']['pkts_toclient']
        flow['Transmitted bytes'] = flow_record['flow']['bytes_toserver']
        flow['Transmitted packets'] = flow_record['flow']['pkts_toserver']
        flow['Total bytes'] = flow['Received bytes'] + flow['Transmitted bytes']
        flow['Total packets'] = flow['Received packets'] + flow['Transmitted packets'] 
        
        return flow

    def prepare_values(self, flow):
        norm_cols = ['Duration', 'Received bytes', 'Received packets',
        'Transmitted bytes', 'Transmitted packets', 'Total bytes',
        'Total packets']
        df = self.df[norm_cols]
        max_vals = df.max()
        # Normalization
        for col in norm_cols:
            flow[col] /= max_vals[col]
            if flow[col] > 1.0:
                flow[col] = 1.0

        if flow['Protocol'] == 'udp':
            flow['Protocol_udp'] = 1
            flow['Protocol_tcp'] = 0
        else:
            flow['Protocol_udp'] = 0
            flow['Protocol_tcp'] = 1

        if flow['Application protocol'] == '-':
            flow['Application protocol_-'] = 1
            flow['Application protocol_dns'] = 0
            flow['Application protocol_http'] = 0
            flow['Application protocol_https'] = 0
            flow['Application protocol_tls'] = 0

        elif flow['Application protocol'] == 'http':
            flow['Application protocol_-'] = 0
            flow['Application protocol_dns'] = 0
            flow['Application protocol_http'] = 1
            flow['Application protocol_https'] = 0
            flow['Application protocol_tls'] = 0

        elif flow['Application protocol'] == 'https':
            flow['Application protocol_-'] = 0
            flow['Application protocol_dns'] = 0
            flow['Application protocol_http'] = 0
            flow['Application protocol_https'] = 1
            flow['Application protocol_tls'] = 0

        elif flow['Application protocol'] == 'tls':
            flow['Application protocol_-'] = 0
            flow['Application protocol_dns'] = 0
            flow['Application protocol_http'] = 0
            flow['Application protocol_https'] = 0
            flow['Application protocol_tls'] = 1 

        elif flow['Application protocol'] == 'dns':
            flow['Application protocol_-'] = 0 
            flow['Application protocol_dns'] = 1 
            flow['Application protocol_http'] = 0
            flow['Application protocol_https'] = 0
            flow['Application protocol_tls'] = 0

        del flow['Application protocol']
        del flow['Protocol']
        return flow
        
    def predict(self, flow):
        if flow['event_type'] == 'flow':
            if 'app_proto' in flow:
                if flow['app_proto'] == 'ntp':
                    return None
            flow = self.get_values(flow)
            flow = self.prepare_values(flow) 
            flow_df = pd.DataFrame(flow, index=[0,])
            print(flow_df)
            flow_numpy = flow_df.to_numpy()
            try:
                return self.model.predict(flow_numpy)
            except:
                return None

        return None
