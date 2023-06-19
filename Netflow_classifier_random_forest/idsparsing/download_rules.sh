#!/bin/bash

mkdir -p data
if [ "$(ls -A data)" ]; then
   echo "Directory 'data' is not empty!"
   exit
fi

# Suricata classification labels
wget https://raw.githubusercontent.com/OISF/suricata/master/etc/classification.config -O classification.config

# By default Suricata fetches the Emerging Threats (ET) Open ruleset with the `suricata-update` tool
wget https://rules.emergingthreats.net/open/suricata-7/emerging.rules.tar.gz
tar -xf emerging.rules.tar.gz
mv rules data/ET_rules
rm emerging.rules.tar.gz

# Suricata also includes some rules in its GitHub repo
git clone https://github.com/OISF/suricata.git
mv suricata/rules data/suricata_rules
rm -rf suricata

# Snort.org provides both Snort v2.9 community rules...
wget https://www.snort.org/downloads/community/community-rules.tar.gz
tar -xf community-rules.tar.gz
mv community-rules data/snort2_rules
rm community-rules.tar.gz
# ...and Snort v3.0 community rules
wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
tar -xf snort3-community-rules.tar.gz
mv snort3-community-rules data/snort3_rules
rm snort3-community-rules.tar.gz

# Wazuh is delivered with the latest ruleset on each release.
# Manual update is no longer necessary nor supported.
git clone https://github.com/wazuh/wazuh.git
mv wazuh/ruleset/rules data/wazuh_rules
rm -rf wazuh
