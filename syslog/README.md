# Inference from kafka stream (outlierdetectionANDclassification_syslog_inference_fromkafka.py)
Requires spark
Requires kafka stream with csv formatted samples in column order:
```
["message","label"]
```
Run script with
```
spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.0 --driver-memory 15g outlierdetectionANDclassification_syslog_inference_fromkafka.py
```

# Inference from syslog file (outlierdetectionANDclassification_syslog_inference.py) (format: 1 syslog entry per line)
python outlierdetectionANDclassification_syslog_inference.py --inputfile INPUTFILENAME