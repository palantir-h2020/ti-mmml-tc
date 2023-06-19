import json
from idsparsing.common import wazuh_rule_id__to__threat_label_and_category


def parse_wazuh_log_line(line):
    try:
        return json.loads(line)
    except:
        return None

'''
Output format towards RR (from https://confluence.i2cat.net/display/PAL/Data+and+Event+Streams+Definition)
topic: ti.threat_findings_syslog
sample: threatresults_syslog_new.json

[
	{
	"AnomalyDetectionSyslog": "Mar  4 14:41:06 kafka-broker-2 sshd[9267]: Failed password for invalid user localadmin from 10.225.1.72 port 37576 ssh2",
	"Threat_Label": "hydra-ssh",
	"Classification_Confidence": 0.45288336760415016,
	"Outlier_Score": "8.617603",
	"Source_IP": "10.101.41.33"
	}
]
'''
def parsed_wazuh_alert_to_TCAM_event(alert):
    event = {}
    event['IDS_Source'] = 'wazuh'

    if 'rule' in alert and 'id' in alert['rule']:
        rule_id = int(alert['rule']['id'])
    else:
        rule_id = None
    event['rule_id'] = rule_id

    if 'agent' in alert and 'id' in alert['agent']:
        # '000' is the ID of the Wazuh Manager
        event['wazuh_agent_id'] = alert['agent']['id']
    else:
        event['wazuh_agent_id'] = None

    if 'rule' in alert and 'mitre' in alert['rule']:
        event['mitre'] = alert['rule']['mitre']
    else:
        event['mitre'] = None

    if 'full_log' in alert:
        event['AnomalyDetectionSyslog'] = alert['full_log']
    else:
        event['AnomalyDetectionSyslog'] = None

    event['Threat_Label'],event['Threat_Category'] = wazuh_rule_id__to__threat_label_and_category[rule_id]
    if rule_id==86601 and "ET POLICY HTTP POST on unusual Port Possibly Hostile" in alert['rule']['description']:
        event['Threat_Label']='medicaldb'
        event['Threat_Category']='unauthorized_access'

    if 'agent' in alert and 'ip' in alert['agent']:
        event['Source_IP'] = alert['agent']['ip']
    else:
        event['Source_IP'] = None

    event['Classification_Confidence'] = None   # not relevant for Wazuh logs
    event['Outlier_Score'] = None   # not relevant for Wazuh logs
    event["MITRE_ATT&CK_Classification"] = []
    event["MITRE_ATT&CK_Knowledge_Base"] = "Enterprise 12.1"

    return event
