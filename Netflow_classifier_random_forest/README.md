Requires spark 3.0
Requires kafka stream with csv formatted samples in column order:
```
['ts','te','sa','da','sp','dp',"features","anomalyScore"]
```
where "features" are the preprocessed Vector Assembled features from outlier detection and "anomalyScore" is the anomaly score from outlier detection

Run script with
```
spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.0 --driver-memory 15g "distributed_netflow_inference (classifier).py"
```