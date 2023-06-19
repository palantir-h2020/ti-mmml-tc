import json
import os
from idsparsing.common import snort_suricata_classtype__to__threat_label_and_category
from idsparsing.utils import read_gid_sid_rev_mapping, read_classification_cfg


# Set it to True for an OPTIONAL double-check
if True:
    fname = 'gid_sid_rev__to__classtype__mapping.csv'
    if not os.path.exists(fname):
        print("'%s' not found! Check README.md" % fname)
        exit()
    gid_sid_rev__to__classtype = read_gid_sid_rev_mapping(fname)
    # print(gid_sid_rev__to__classtype)
else:
    gid_sid_rev__to__classtype = None


fnanme = 'classification.config'
if not os.path.exists(fname):
    print("'%s' not found! Check README.md" % fname)
    exit()
short_name__to_desc__and_prio = read_classification_cfg('classification.config')
# print(short_name__to_desc__and_prio)
short_desc__to__short_name = {}
for k,v in short_name__to_desc__and_prio.items():
    short_desc__to__short_name[ v['short description'] ] = k
# print(short_desc__to__short_name)


def parse_suricata_log_line(line):
    try:
        return json.loads(line)
    except:
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
def parsed_suricata_alert_to_TCAM_event(alert):
    event = {}
    event['IDS_Source'] = 'suricata'

    threat_finding = {}
    event['Threat_Finding'] = threat_finding

    if 'timestamp' in alert:
        threat_finding['Time_Start'] = alert['timestamp'].split('.')[0]
    else:
        threat_finding['Time_Start'] = None

    threat_finding['Time_End'] = None   # not available in Suricata logs
    threat_finding['Time_Duration'] = None  # not available in Suricata logs

    if 'src_ip' in alert:
        threat_finding['Source_Address'] = alert['src_ip']
    else:
        threat_finding['Source_Address'] = None

    if 'dest_ip' in alert:
        threat_finding['Destination_Address'] = alert['dest_ip']
    else:
        threat_finding['Destination_Address'] = None

    if 'src_port' in alert:
        threat_finding['Source_Port'] = int(alert['src_port'])
    else:
        threat_finding['Source_Port'] = None

    if 'dest_port' in alert:
        threat_finding['Destination_Port'] = int(alert['dest_port'])
    else:
        threat_finding['Destination_Port'] = None

    if 'proto' in alert:
        threat_finding['Protocol'] = alert['proto']
    else:
        threat_finding['Protocol'] = None

    threat_finding['Flag'] = None   # not available in Suricata logs
    threat_finding['Soure_tos'] = None  # not available in Suricata logs

    # TODO!
    if 'flow' in alert:
        if 'pkts_toserver' in alert['flow'] and 'pkts_toclient' in alert['flow']:
            threat_finding['Input_packets'] = alert['flow']['pkts_toserver'] + alert['flow']['pkts_toclient']
        else:
            threat_finding['Input_packets'] = None

        if 'bytes_toserver' in alert['flow'] and 'bytes_toclient' in alert['flow']:
            threat_finding['Input_bytes'] = alert['flow']['bytes_toserver'] + alert['flow']['bytes_toclient']
        else:
            threat_finding['Input_bytes'] = None
    else:
        threat_finding['Input_packets'] = None
        threat_finding['Input_bytes'] = None

    if 'alert' in alert and 'category' in alert['alert']:
        category = alert['alert']['category']
        if category in short_desc__to__short_name:
            classtype = short_desc__to__short_name[category]
        else:
            classtype = None
    else:
        classtype = None

    # Suricata already includes classtype. We can optionally also retrieve it from gid:sid:rev as double check.
    # if gid_sid_rev__to__classtype is not None:
    #     if 'alert' in alert and 'gid' in alert['alert'] and 'signature_id' in alert['alert'] and 'rev' in alert['alert']:
    #         gid = alert['alert']['gid']
    #         sid = alert['alert']['signature_id']
    #         rev = alert['alert']['rev']
    #         gsr = '%s:%s:%s' % (gid,sid,rev)
    #         if gsr in gid_sid_rev__to__classtype:
    #             classtype__from__gid_sid_rev = gid_sid_rev__to__classtype[gsr]
    #             print('classtype from alert:', classtype)
    #             print('classtype__from__gid_sid_rev:', classtype__from__gid_sid_rev)

    event['Threat_Label'],event['Threat_Category'] = snort_suricata_classtype__to__threat_label_and_category[classtype]
    event['Classification_Confidence'] = None   # not relevant for Suricata logs
    event['Outlier_Score'] = None   # not relevant for Suricata logs
    event["MITRE_ATT&CK_Classification"] = []
    event["MITRE_ATT&CK_Knowledge_Base"] = "Enterprise 12.1"
    return event
