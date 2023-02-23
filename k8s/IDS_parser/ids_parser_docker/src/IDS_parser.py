from common import parse_filebeat_msg
from kafka_utils import *
from pprint import pprint
from snort2 import parse_snort2_alert_fast_log_line, parsed_snort2_alert_to_TCAM_event
from suricata import parse_suricata_log_line, parsed_suricata_alert_to_TCAM_event
from wazuh import parse_wazuh_log_line, parsed_wazuh_alert_to_TCAM_event
import os


if 'KAFKA_BROKERS_CSV' in os.environ:
    KAFKA_BROKERS_CSV = os.environ['KAFKA_BROKERS_CSV']
else:
    print('KAFKA_BROKERS_CSV env var required')
    exit()

if 'KAFKA_TOPIC_IN_SNORT2' in os.environ:
    KAFKA_TOPIC_IN_SNORT2 = os.environ['KAFKA_TOPIC_IN_SNORT2']
else:
    KAFKA_TOPIC_IN_SNORT2 = None

if 'KAFKA_TOPIC_IN_SURICATA' in os.environ:
    KAFKA_TOPIC_IN_SURICATA = os.environ['KAFKA_TOPIC_IN_SURICATA']
else:
    KAFKA_TOPIC_IN_SURICATA = None

if 'KAFKA_TOPIC_IN_WAZUH' in os.environ:
    KAFKA_TOPIC_IN_WAZUH = os.environ['KAFKA_TOPIC_IN_WAZUH']
else:
    KAFKA_TOPIC_IN_WAZUH = None

if all([x is None for x in [KAFKA_TOPIC_IN_SNORT2, KAFKA_TOPIC_IN_SURICATA, KAFKA_TOPIC_IN_WAZUH]]):
    print('At least one KAFKA_TOPIC_IN_[SNORT2|SURICATA|WAZUH] env var is required')
    exit()

if 'KAFKA_TOPIC_OUT_NETFLOW' in os.environ:
    KAFKA_TOPIC_OUT_NETFLOW = os.environ['KAFKA_TOPIC_OUT_NETFLOW']
else:
    print('KAFKA_TOPIC_OUT_NETFLOW env var required')
    exit()

if 'KAFKA_TOPIC_OUT_SYSLOG' in os.environ:
    KAFKA_TOPIC_OUT_SYSLOG = os.environ['KAFKA_TOPIC_OUT_SYSLOG']
else:
    print('KAFKA_TOPIC_OUT_SYSLOG env var required')
    exit()

if 'VERBOSITY' in os.environ:
    if os.environ['VERBOSITY'] == 'DEBUG':
        VERBOSITY = logging.DEBUG
    elif os.environ['VERBOSITY'] == 'INFO':
        VERBOSITY = logging.INFO
    elif os.environ['VERBOSITY'] == 'WARNING':
        VERBOSITY = logging.WARNING
    elif os.environ['VERBOSITY'] == 'ERROR':
        VERBOSITY = logging.ERROR
    elif os.environ['VERBOSITY'] == 'CRITICAL':
        VERBOSITY = logging.CRITICAL
    else:
        print('VERBOSITY env var has invalid value')
        exit()
else:
    VERBOSITY = logging.INFO

logger = logging.getLogger('ids_parser')
logger.setLevel(VERBOSITY)
consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(VERBOSITY)
logger.addHandler(consoleHandler)
formatter = logging.Formatter('%(asctime)s [%(module)s] %(levelname)s %(message)s')
consoleHandler.setFormatter(formatter)

################################################################################

def proc_msg(topic, value, producer):
    global msg_out_cnt

    # Check if data has been correctly decoded (error already logged by kafka_utils)
    if value is None:
        return

    if topic == KAFKA_TOPIC_IN_SNORT2:
        ids_name = 'Snort2'
        parse_log_line_fx = parse_snort2_alert_fast_log_line
        parsed_alert_to_TCAM_event_fx = parsed_snort2_alert_to_TCAM_event
    elif topic == KAFKA_TOPIC_IN_SURICATA:
        ids_name = 'Suricata'
        parse_log_line_fx = parse_suricata_log_line
        parsed_alert_to_TCAM_event_fx = parsed_suricata_alert_to_TCAM_event
    elif topic == KAFKA_TOPIC_IN_WAZUH:
        ids_name = 'Wazuh'
        parse_log_line_fx = parse_wazuh_log_line
        parsed_alert_to_TCAM_event_fx = parsed_wazuh_alert_to_TCAM_event
    else:
        logger.error('Unexpected Kafka topic \'%s\'' % topic)
        return

    filebeat_msg = parse_filebeat_msg(value)
    if filebeat_msg is None or 'message' not in filebeat_msg:
        logger.error('Cannot parse Filebeat msg:\n%s' % value)
        return
    parsed_alert = parse_log_line_fx(filebeat_msg['message'])
    if parsed_alert is None:
        logger.error('Cannot parse %s log line:\n%s' % (ids_name, filebeat_msg['message']))
        return
    TCAM_event = parsed_alert_to_TCAM_event_fx(parsed_alert)
    if TCAM_event is None:
        logger.error('Cannot process %s alert\n%s' % (ids_name, parsed_alert))
        return

    # print(parsed_alert)
    # pprint(TCAM_event)

    # Snort/Suricata alerts are always propagated to RR.
    # Wazuh alerts are propagated to RR based on a whitelist (whether the rule ID is known and relevant).
    if topic == KAFKA_TOPIC_IN_WAZUH and (TCAM_event['Threat_Label'],TCAM_event['Threat_Category'])==('UNKNOWN','UNKNOWN'):
        logger.debug('Wazuh alert ignored (rule ID %d)' % (TCAM_event['rule_id']))
        return

    if topic in [KAFKA_TOPIC_IN_SNORT2, KAFKA_TOPIC_IN_SURICATA]:
        KAFKA_TOPIC_OUT = KAFKA_TOPIC_OUT_NETFLOW
    elif topic == KAFKA_TOPIC_IN_WAZUH:
        KAFKA_TOPIC_OUT = KAFKA_TOPIC_OUT_SYSLOG
    else:
        return
    producer.send(KAFKA_TOPIC_OUT, key='IDS-parser-msg-%d' % msg_out_cnt, value=TCAM_event)
    msg_out_cnt += 1


if __name__ == "__main__":
    logger.info('KAFKA_BROKERS_CSV = %s' % KAFKA_BROKERS_CSV)
    logger.info('KAFKA_TOPIC_IN_SNORT2 = %s' % KAFKA_TOPIC_IN_SNORT2)
    logger.info('KAFKA_TOPIC_IN_SURICATA = %s' % KAFKA_TOPIC_IN_SURICATA)
    logger.info('KAFKA_TOPIC_OUT_NETFLOW = %s' % KAFKA_TOPIC_OUT_NETFLOW)
    logger.info('KAFKA_TOPIC_OUT_SYSLOG = %s' % KAFKA_TOPIC_OUT_SYSLOG)
    if VERBOSITY == logging.DEBUG:
        logger.info('VERBOSITY = DEBUG')
    elif VERBOSITY == logging.INFO:
        logger.info('VERBOSITY = INFO')
    elif VERBOSITY == logging.WARNING:
        logger.info('VERBOSITY = WARNING')
    elif VERBOSITY == logging.ERROR:
        logger.info('VERBOSITY = ERROR')
    elif VERBOSITY == logging.CRITICAL:
        logger.info('VERBOSITY = CRITICAL')

    logger.info('\x1b[1;32;40m IDS parser\x1b[0m')

    msg_out_cnt = 0
    # group_id is set to non-None group_id to avoid consuming same events across re-runs of IDS_parser.
    consumer = build_kafka_consumer(KAFKA_BROKERS_CSV, None, 'group_IDS_parser', 'csv', 'csv')
    topics_in = []
    if KAFKA_TOPIC_IN_SNORT2 is not None:
        topics_in.append(KAFKA_TOPIC_IN_SNORT2)
    if KAFKA_TOPIC_IN_SURICATA is not None:
        topics_in.append(KAFKA_TOPIC_IN_SURICATA)
    if KAFKA_TOPIC_IN_WAZUH is not None:
        topics_in.append(KAFKA_TOPIC_IN_WAZUH)
    consumer.subscribe(topics_in)
    producer = build_kafka_producer(KAFKA_BROKERS_CSV, 'json', 'json')

    logger.info('Waiting for new messages from topics \'%s\', \'%s\' and \'%s\'...' % (KAFKA_TOPIC_IN_SNORT2, KAFKA_TOPIC_IN_SURICATA, KAFKA_TOPIC_IN_WAZUH))
    logger.info('{topic}:{partition}:{offset} key={key} value={value}')
    msg_cnt = 0
    try:
        for message in consumer:
            logger.info("%s:%d:%d key=%s value=%s" % (message.topic, message.partition,
                                          message.offset, message.key,
                                          message.value))
            proc_msg(message.topic, message.value, producer)
            msg_cnt += 1
    except KeyboardInterrupt:
        logger.info('Done')
    logger.info('Processed %d messages' % msg_cnt)
