import csv
from os import path

# check if sample is in csv log file
def check_recorded(log_f, log_dir, f):
    with open(log_dir+log_f, encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        header = next(reader)
        for row in reader:
            row = dict(zip(header,row))
            if row['Filename'] == path.basename(f):
                return True
        return False

# return md5 hash of the submited sample
def get_hash(sample_id: str, client) -> str:
    return client.overview_report(sample_id)['sample']['md5']

# create csv file name
def create_file_name(directory):
    log_f = directory.replace('/','_')
    if log_f.endswith('_'):
        log_f = log_f[:-1] + ".csv"
    else:
        log_f = log_f + ".csv"
    return log_f

# write csv header if csv file doest exists
def write_header(file, log_dir):
    if not path.exists(log_dir+file):
        header = ['Filename', 'Sample_id', 'md5_hash']
        with open(log_dir+file, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(header)

# log sample id and from witch directory its from
def log(sample_id : str, filename : str, log_f : str, client, log_dir):
    data = [filename, sample_id, get_hash(sample_id, client)]
    with open(log_dir+log_f, 'a') as f:
        # create the csv writer
        writer = csv.writer(f)
        # write a row to the csv file
        writer.writerow(data)


