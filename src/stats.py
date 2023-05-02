"""
stats.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Module with implementation of class to keep track about process Suricata log entries during live classification
"""

class Stats:
    """
    Class to keep track about process logs and classified flows during live capture.
    """

    log_cnt = 0 # Number of proccessed log records
    malware = 0 # Overall number of classified malware flows
    normal = 0 # Overall number of classified normal flows
    tmp_malware = 0 # Number of classified malware flows during period of time
    tmp_normal = 0 # Number of classified normal flows during period of time
    flow_cnt = 1 # Number of proccessed flows
    found_ioc = [] # List of found iocs
    
    def __init__(self):
        pass

    def inc_log_cnt(self):
        """
        Increment number of processed log entries
        """
        self.log_cnt += 1

    def increment_malware(self):
        """
        Increment number of processed flows and classified malware flows
        """
        self.tmp_malware += 1
        self.malware += 1
        self.flow_cnt += 1

    def increment_normal(self):
        """
        Increment number of processed flows and classified normal flows
        """
        self.tmp_normal += 1
        self.normal += 1 
        self.flow_cnt += 1

    def reset(self):
        """
        Recet temporary variables to 0
        """
        self.tmp_malware = 0
        self.tmp_normal = 0
    
    def add_ioc(self, ioc):
        """
        Add IOC to the list and remove possible duplicants
        """
        self.found_ioc.append(ioc)
        self.found_ioc = [*set(self.found_ioc)]


    def score(self):
        """
        Print overall score about classification and found IOC's
        """
        print("--------------------------------------")
        print("Percentage of normal flows: ", round(((self.normal/self.flow_cnt)*100),2))
        print("Percentage of malware flows: ", round(((self.malware/self.flow_cnt)*100),2))
        print("Number of IOC's: ", len(self.found_ioc))

