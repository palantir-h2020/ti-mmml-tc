import json
from collections import defaultdict


# Snort/Suricata
snort_suricata_classtype__to__threat_label_and_category = defaultdict( lambda: ('UNKNOWN','UNKNOWN') )
snort_suricata_classtype__to__threat_label_and_category['successful-dos'] = ('successful-dos', 'dos')
# TODO!


# Wazuh
wazuh_rule_id__to__threat_label_and_category = defaultdict( lambda: ('UNKNOWN','UNKNOWN') )
# TODO!

def parse_filebeat_msg(msg):
    try:
        return json.loads(msg)
    except:
        return None
