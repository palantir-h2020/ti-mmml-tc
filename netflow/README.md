# Introduction

Netflow classifier using the Spark implementation of RandomForest.

## Requirements
Requires spark 3.0
Requires elephas implementation in this repo (install with setup.py)
Requires kafka stream with csv formatted samples in column order:
```
['ts','te','sa','da','sp','dp',"features","anomalyScore"]
```
where "features" are the preprocessed Vector Assembled features from outlier detection and "anomalyScore" is the anomaly score from outlier detection

## Usage

Run script with
```
spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.0 --driver-memory 15g "distributed_netflow_inference (classifier).py"
```

## License
[GPL 3.0](https://choosealicense.com/licenses/gpl-3.0/#)
 
