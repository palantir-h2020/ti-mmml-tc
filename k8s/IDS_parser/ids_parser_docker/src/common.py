import json
from collections import defaultdict


# Snort/Suricata
snort_suricata_classtype__to__threat_label_and_category = defaultdict( lambda: ('UNKNOWN','UNKNOWN') )
"""
import pandas as pd
from io import StringIO
# From classification.config
csvString='''benign,not-suspicious,Not Suspicious Traffic,3
...
malware,command-and-control,Malware Command and Control Activity Detected,1
'''
csvStringIO = StringIO(csvString)
df = pd.read_csv(csvStringIO, sep=",", header=None, names=['category','shortname','short description','priority'], usecols=['category','shortname'])
snort_suricata_classtype__to__threat_label_and_category = {}
d = {}
for row in df.to_dict(orient='records'):
    d[row['shortname']] = (row['shortname'],row['category'])
for x in d:
    print('snort_suricata_classtype__to__threat_label_and_category[\'%s\'] =' % x, snort_suricata_classtype__to__threat_label_and_category[x])
"""
snort_suricata_classtype__to__threat_label_and_category['not-suspicious'] = ('not-suspicious', 'benign')
snort_suricata_classtype__to__threat_label_and_category['unknown'] = ('unknown', 'unknown')
snort_suricata_classtype__to__threat_label_and_category['bad-unknown'] = ('bad-unknown', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['attempted-recon'] = ('attempted-recon', 'info-leak')
snort_suricata_classtype__to__threat_label_and_category['successful-recon-limited'] = ('successful-recon-limited', 'info-leak')
snort_suricata_classtype__to__threat_label_and_category['successful-recon-largescale'] = ('successful-recon-largescale', 'info-leak')
snort_suricata_classtype__to__threat_label_and_category['attempted-dos'] = ('attempted-dos', 'dos')
snort_suricata_classtype__to__threat_label_and_category['successful-dos'] = ('successful-dos', 'dos')
snort_suricata_classtype__to__threat_label_and_category['attempted-user'] = ('attempted-user', 'privilege-escalation')
snort_suricata_classtype__to__threat_label_and_category['unsuccessful-user'] = ('unsuccessful-user', 'privilege-escalation')
snort_suricata_classtype__to__threat_label_and_category['successful-user'] = ('successful-user', 'privilege-escalation')
snort_suricata_classtype__to__threat_label_and_category['attempted-admin'] = ('attempted-admin', 'privilege-escalation')
snort_suricata_classtype__to__threat_label_and_category['successful-admin'] = ('successful-admin', 'privilege-escalation')
snort_suricata_classtype__to__threat_label_and_category['rpc-portmap-decode'] = ('rpc-portmap-decode', 'unknown')
snort_suricata_classtype__to__threat_label_and_category['shellcode-detect'] = ('shellcode-detect', 'malware')
snort_suricata_classtype__to__threat_label_and_category['string-detect'] = ('string-detect', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['suspicious-filename-detect'] = ('suspicious-filename-detect', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['suspicious-login'] = ('suspicious-login', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['system-call-detect'] = ('system-call-detect', 'unknown')
snort_suricata_classtype__to__threat_label_and_category['tcp-connection'] = ('tcp-connection', 'unknown')
snort_suricata_classtype__to__threat_label_and_category['trojan-activity'] = ('trojan-activity', 'malware')
snort_suricata_classtype__to__threat_label_and_category['unusual-client-port-connection'] = ('unusual-client-port-connection', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['network-scan'] = ('network-scan', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['denial-of-service'] = ('denial-of-service', 'dos')
snort_suricata_classtype__to__threat_label_and_category['non-standard-protocol'] = ('non-standard-protocol', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['protocol-command-decode'] = ('protocol-command-decode', 'unknown')
snort_suricata_classtype__to__threat_label_and_category['web-application-activity'] = ('web-application-activity', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['web-application-attack'] = ('web-application-attack', 'network-attack')
snort_suricata_classtype__to__threat_label_and_category['misc-activity'] = ('misc-activity', 'unknown')
snort_suricata_classtype__to__threat_label_and_category['misc-attack'] = ('misc-attack', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['icmp-event'] = ('icmp-event', 'unknown')
snort_suricata_classtype__to__threat_label_and_category['inappropriate-content'] = ('inappropriate-content', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['policy-violation'] = ('policy-violation', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['default-login-attempt'] = ('default-login-attempt', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['targeted-activity'] = ('targeted-activity', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['exploit-kit'] = ('exploit-kit', 'network-attack')
snort_suricata_classtype__to__threat_label_and_category['external-ip-check'] = ('external-ip-check', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['domain-c2'] = ('domain-c2', 'malware')
snort_suricata_classtype__to__threat_label_and_category['pup-activity'] = ('pup-activity', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['credential-theft'] = ('credential-theft', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['social-engineering'] = ('social-engineering', 'suspicious')
snort_suricata_classtype__to__threat_label_and_category['coin-mining'] = ('coin-mining', 'malware')
snort_suricata_classtype__to__threat_label_and_category['command-and-control'] = ('command-and-control', 'malware')


# Wazuh
wazuh_rule_id__to__threat_label_and_category = defaultdict( lambda: ('UNKNOWN','UNKNOWN') )
# TODO!

def parse_filebeat_msg(msg):
    try:
        return json.loads(msg)
    except:
        return None
