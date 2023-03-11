import json
from os import path, listdir

def create_report_file(directory, appendix = ""):
    log_f = directory.replace('/','_')
    if log_f.endswith('_'):
        log_f = log_f[:-1] + appendix + ".json"
    else:
        log_f = log_f + appendix + ".json"
    return log_f

def create_report(report, log_f, log_dir):
    json_object = json.dumps(report, indent=4)
    with open(path.join(log_dir, log_f), "w") as outfile:
        outfile.write(json_object)

def check_downloaded(log_dir, f):
    f_base = path.basename(f)
    for file in listdir(log_dir):
        if path.splitext(file)[0] == path.splitext(f_base)[0]:
            return True
    return False