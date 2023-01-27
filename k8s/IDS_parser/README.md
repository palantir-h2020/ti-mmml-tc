# IDS parser

These scripts setup the `IDS parser` component together with a local `Kafka` container and a `dummy IDS producer` and a `dummy RR consumer`.

## Run tests outside Docker

### Requirements

Download and parse rules (i.e. create gid:sid:rev -> classtype mapping)

```shell
cd ids_parser_docker/src
./download_rules.sh
python create__gid_sid_rev__mapping.py
```

### Tests

```shell
cd ids_parser_docker/src
python test_snort2_parser.py
python test_suricata_parser.py
```

## Run in Docker

### Requirements (based on Ubuntu 20.04.3 LTS)

Install and configure Docker based on https://github.com/palantir-h2020/ti-mmml-ad/tree/master/netflow-midas#requirements-tested-on-ubuntu-20043-lts.

### Manual run in Docker

Open three terminals
```
./clean_docker.sh
./build_run_config_kafka_docker.sh
./build_run_ids_parser_docker.sh
```

Once Kafka and IDS parser are ready (i.e. IDS parser shows `Waiting for new messages...`), run the next set of commands on the other two terminals.

```
./build_run_dummy_rr_consumer_docker.sh
```

```
./build_run_dummy_ids_producer_docker.sh
```

Press ENTER multiple times to send test messages.

### Automated run in Docker

```
./run_all_in_tmux_docker.sh
```
Once all the terminals are ready  (i.e. all the 3 terminals show `Waiting for new messages...`), press ENTER multiple times to send test messages.
