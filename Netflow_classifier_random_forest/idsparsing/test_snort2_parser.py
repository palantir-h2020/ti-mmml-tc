import json
from pprint import pprint
from idsparsing.snort2 import parse_snort2_alert_fast_log_line, parsed_snort2_alert_to_TCAM_event


if __name__ == "__main__":

    with open('sample/snort_alerts.txt', 'r') as f:
        snort2_lines_sample = f.readlines()

    for line in snort2_lines_sample:
        line = line.strip()
        try:
            alert = parse_snort2_alert_fast_log_line(line)
            if alert is None:
                print('-> Cannot parse Snort 2 log line:', line)
                continue
            print(line)
            print(alert)
            event = parsed_snort2_alert_to_TCAM_event(alert)
            pprint(event)
            event_json_str = json.dumps(event)
            print(event_json_str)
        except Exception as e:
            print('Exception "%s: %s" raised while parsing line "%s"' % (e.__class__.__name__, e, line))
            input('Press ENTER')
        print()
