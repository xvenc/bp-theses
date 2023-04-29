"""
csv_writer.py
Bachelor thesis 2022/2023
Author: Václav Korvas VUT FIT 3BIT 
Functions for work with csv log file (writing new record, checking if was already recorded) 
"""

import csv
from os import path

def check_recorded(log_f, log_dir, f):
    """
    Function to check if sample is logged in csv log file
    """
    with open(log_dir+log_f, encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        header = next(reader)
        for row in reader:
            row = dict(zip(header,row))
            if row['Filename'] == path.basename(f):
                return True
        return False

def get_hash(sample_id: str, client) -> str:
    """
    Function to retrive md5 hash of a sample from triage 
    """
    return client.overview_report(sample_id)['sample']['md5']

def create_file_name(directory):
    """
    Function to create correct log file name based on malware family name
    """
    log_f = directory.replace('/','_')
    if log_f.endswith('_'):
        log_f = log_f[:-1] + ".csv"
    else:
        log_f = log_f + ".csv"
    return log_f

def write_header(file, log_dir):
    """
    Write header to a newly created csv log file
    """
    if not path.exists(log_dir+file):
        header = ['Filename', 'Sample_id']
        with open(log_dir+file, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)

def log(sample_id : str, filename : str, log_f : str, client, log_dir):
    """
    Log all important information into csv file, like sample id and filename 
    """
    data = [filename, sample_id]
    with open(path.join(log_dir, log_f), 'a') as f:
        # create the csv writer
        writer = csv.writer(f)
        # write a row to the csv file
        writer.writerow(data)