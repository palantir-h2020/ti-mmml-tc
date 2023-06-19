import datetime
import os
import re
from idsparsing.common import snort_suricata_classtype__to__threat_label_and_category
from idsparsing.utils import read_gid_sid_rev_mapping


fname = 'gid_sid_rev__to__classtype__mapping.csv'
if not os.path.exists(fname):
    print("'%s' not found! Check README.md" % fname)
    exit()
gid_sid_rev__to__classtype = read_gid_sid_rev_mapping(fname)
# print(gid_sid_rev__to__classtype)


REGEX = r'(\d{2})\/(\d{2})(?:\/(\d{4}))?-(\d{2}:\d{2}:\d{2}\.\d{1,6})' # month, day, year, time (year is optional)
REGEX += r'.*\[(\d+):(\d+):(\d+)\]' # gid, sid, rev
REGEX += r'(?:(.*)) \[\*\*\]' # msg (optional)
REGEX += r'.* ((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(\d+))? -> ((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(\d+))?' # src_ip, src_port, dst_ip, dst_port (src_port and dst_port are optional)
CLS_REGEX = r'\[Classification: ([a-zA-Z0-9 ]+)\]'
PRIORITY_REGEX = r'\[Priority: (\d+)\]'


def parse_snort2_alert_fast_log_line(line):
    alert = {}
    m = re.search(REGEX, line)
    if m:
        groups = m.groups()
        # month comes before day ( checked from ts_print() in snort/src/util.c )
        alert['month'] = groups[0]
        alert['day'] = groups[1]
        alert['year'] = groups[2] # might be None
        alert['time'] = groups[3]

        alert['gid'] = groups[4]
        alert['sid'] = groups[5]
        alert['rev'] = groups[6]

        alert['msg'] = groups[7].strip()
        if alert['msg'] == '': alert['msg'] = None

        alert['src_ip'] = groups[8]
        alert['src_port'] = groups[9] # might be None
        alert['dst_ip'] = groups[10]
        alert['dst_port'] = groups[11] # might be None

        m2 = re.search(CLS_REGEX, line)
        if m2:
            alert['classification'] = m2.groups()[0]
        else:
            alert['classification'] = None

        m3 = re.search(PRIORITY_REGEX, line)
        if m3:
            alert['priority'] = m3.groups()[0]
        else:
            alert['priority'] = None

        if '{TCP}' in line:
            alert['protocol'] = 'TCP'
        elif '{UDP}' in line:
            alert['protocol'] = 'UDP'
        elif '{ICMP}' in line:
            alert['protocol'] = 'ICMP'
        else:
            alert['protocol'] = None

        alert['raw_line'] = line

        return alert
    else:
        return None

'''
Output format towards RR (from https://confluence.i2cat.net/display/PAL/Data+and+Event+Streams+Definition)
topic: ti.threat_findings_netflow
sample: threatfindings_new.json

[
 {
 "Threat_Finding": {
  "Time_Start": "2021-04-29 14:06:12",
  "Time_End": "2021-04-29 14:07:17",
  "Time_Duration": "64",
  "Source_Address": "87.236.215.56",
  "Destination_Address": "10.0.2.108",
  "Source_Port": 80,
  "Destination_Port": 61892,
  "Protocol": "TCP",
  "Flag": "...AP.S.",
  "Soure_tos": 0,
  "Input_packets": 3,
  "Input_bytes": 848
 },
 "Threat_Label": "Miuref",
 "Threat_Category": "Botnet",
 "Classification_Confidence": 0.32560316405960427,
 "Outlier_Score": 0.5544447557709556
 }
]
'''
def parsed_snort2_alert_to_TCAM_event(alert):
    event = {}
    event['IDS_Source'] = 'snort'

    threat_finding = {}
    event['Threat_Finding'] = threat_finding

    if 'year' in alert and alert['year'] is not None:
        year = alert['year']
    else:
        year = datetime.date.today().year

    if 'month' in alert and 'day' in alert and 'time' in alert:
        datetime_str = '%s-%s-%s %s' % (year, alert['month'], alert['day'], alert['time'].split('.')[0])
        threat_finding['Time_Start'] = datetime_str
    else:
        threat_finding['Time_Start'] = None

    threat_finding['Time_End'] = None   # not available in Snort logs
    threat_finding['Time_Duration'] = None  # not available in Snort logs

    if 'src_ip' in alert:
        threat_finding['Source_Address'] = alert['src_ip']
    else:
        threat_finding['Source_Address'] = None

    if 'dst_ip' in alert:
        threat_finding['Destination_Address'] = alert['dst_ip']
    else:
        threat_finding['Destination_Address'] = None

    if 'src_port' in alert:
        threat_finding['Source_Port'] = int(alert['src_port']) if alert['src_port'] is not None else None
    else:
        threat_finding['Source_Port'] = None

    if 'dst_port' in alert:
        threat_finding['Destination_Port'] = int(alert['dst_port']) if alert['dst_port'] is not None else None
    else:
        threat_finding['Destination_Port'] = None

    if 'protocol' in alert:
        threat_finding['Protocol'] = alert['protocol']
    else:
        threat_finding['Protocol'] = None

    threat_finding['Flag'] = None   # not available in Snort logs
    threat_finding['Soure_tos'] = None  # not available in Snort logs
    threat_finding['Input_packets'] = None  # not available in Snort logs
    threat_finding['Input_bytes'] = None    # not available in Snort logs

    # Snort 2 does not include the classtype label (Snort 3 does).
    # We can retrieve it from the gid:sid:rev through our mapping read by parsing the ruleset.
    if 'gid' in alert and 'sid' in alert and 'rev' in alert:
        gsr = '%s:%s:%s' % (alert['gid'],alert['sid'],alert['rev'])
        if gsr in gid_sid_rev__to__classtype:
            classtype = gid_sid_rev__to__classtype[gsr]
        else:
            classtype = 'UNKNOWN'
    else:
        classtype = 'UNKNOWN'

    event['Threat_Label'],event['Threat_Category'] = snort_suricata_classtype__to__threat_label_and_category[classtype]

    event['Classification_Confidence'] = None   # not relevant for Snort logs
    event['Outlier_Score'] = None   # not relevant for Snort logs
    event["MITRE_ATT&CK_Classification"] = []
    event["MITRE_ATT&CK_Knowledge_Base"] = "Enterprise 12.1"
    return event
