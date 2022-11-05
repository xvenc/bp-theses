import json
from os import path, listdir
from pathlib import Path

def create_folder(directory):
    if directory[-1] != '/':
            directory += '/'
    if not path.isdir(directory):
        Path(directory).mkdir(parents=True, exist_ok=True)

def create_file(directory):
    log_f = directory.replace('/','_')
    if log_f.endswith('_'):
        log_f = log_f[:-1] + ".json"
    else:
        log_f = log_f + ".json"
    return log_f

def create_malware_folder(directory):
    if directory[-1] != '/':
        directory += '/'
    if not path.isdir(directory):
        Path(directory).mkdir(parents=True, exist_ok=True)

def create_report(report, log_f, log_dir):
    json_object = json.dumps(report, indent=4)
    with open(log_dir+'/'+log_f, "w") as outfile:
        outfile.write(json_object)

def check_downloaded(log_dir, f):
    f_base = path.basename(f)
    for file in listdir(log_dir):
        if path.splitext(file)[0] == path.splitext(f_base)[0]:
            return True
    return False