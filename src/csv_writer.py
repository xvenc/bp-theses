import csv

# return md5 hash of the submited sample
def get_hash(sample_id: str, client) -> str:
    return client.overview_report(sample_id)['sample']['md5']

def create_file_name(directory):
    log_f = directory.replace('/','_')
    if log_f.endswith('_'):
        log_f = log_f[:-1] + ".csv"
    else:
        log_f = log_f + ".csv"
    return log_f


def write_header(file, log_dir):
    header = ['Filename', 'Sample_id', 'mb5_hash']
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


