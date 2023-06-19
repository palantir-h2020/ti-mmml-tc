import csv

def read_gid_sid_rev_mapping(fname):
    with open(fname, 'r') as f:
        reader = csv.reader(f)
        d = {row[0]: row[1] for row in reader}

    return d

def read_classification_cfg(fname):
    with open(fname, 'r') as f:
        lines = f.readlines()

    d = {}
    for line in lines:
        if line[0] in ['#', '\n']:
            # Skip commented or empty lines
            continue

        line = line.strip()
        hdr = 'config classification:'
        line = line[len(hdr):]
        line_ = line.split(',')

        short_name = line_[0].strip()
        d[short_name] = {}
        d[short_name]['short description'] = line_[1].strip()
        d[short_name]['priority'] = line_[2].strip()

    return d
