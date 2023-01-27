import json
from pprint import pprint
from suricata import parse_suricata_log_line, parsed_suricata_alert_to_TCAM_event


if __name__ == "__main__":

    with open('sample/suricata_alerts.json', 'r') as f:
        suricata_lines_sample = f.readlines()

    for line in suricata_lines_sample:
        line = line.strip()
        try:
            alert = parse_suricata_log_line(line)
            if alert is None:
                continue
            print(line)
            print(alert)
            event = parsed_suricata_alert_to_TCAM_event(alert)
            pprint(event)
            event_json_str = json.dumps(event)
            print(event_json_str)
        except Exception as e:
            print('Exception "%s: %s" raised while parsing line "%s"' % (e.__class__.__name__, e, line))
            input('Press ENTER')
        print()
