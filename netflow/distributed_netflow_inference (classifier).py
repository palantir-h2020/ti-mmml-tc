import argparse
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import matplotlib.pyplot as plt
import time
from operator import truediv
from sklearn.preprocessing import StandardScaler
from pyspark.sql import functions as F
import math
from pyspark.sql.functions import monotonically_increasing_id
from pyspark.ml import Pipeline,PipelineModel
from pyspark.sql.types import *
from datetime import datetime
import os.path
from pyspark.ml.evaluation import MulticlassClassificationEvaluator
from pyspark.mllib.evaluation import MulticlassMetrics
from time import mktime
from sklearn.ensemble import IsolationForest
from pyspark_dist_explore import hist
import matplotlib.pyplot as plt
import pickle
from pyspark.sql.window import Window
from pyspark.ml.feature import StandardScaler,VectorAssembler
import collections
from pyspark_iforest.ml.iforest import *
import warnings
from pyspark.ml.feature import StringIndexer,VectorIndexer,IndexToString,StringIndexerModel
import ipaddress
from pyspark.ml.classification import RandomForestClassifier
import json
from sklearn.preprocessing import LabelEncoder
warnings.filterwarnings("ignore")
from pyspark.sql import SparkSession
from pyspark.sql.functions import col

spark = SparkSession.builder.getOrCreate()
spark.sparkContext.setLogLevel('ERROR')
#spark.sparkContext.parallelize((0,25), 6)
		
def runPipeline(batch_df):
	print('Parsing input stream')
	df=batch_df
	if df.count()==0:
		return
	print('shape',df.count())
	outliers=df
	model=PipelineModel.load('spark_netflow_pickled_files/randomforestpipeline')
	predictions = model.transform(outliers)
	
	#########################TODO OUTPUT PREDICTIONS SOMEWHERE================================
	

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('--cutoff', type=float, help='Cutoff point.',default=0.5)
	args = parser.parse_args()
	
	offset="0"
	N=1000
	while True:
		df = spark.read.format("kafka").option("kafka.bootstrap.servers", "localhost:9092").option("subscribe", "Hello-Kafka")
		if os.path.exists("kafkaOffset.txt"):
			f=open("kafkaOffset.txt")
			offset=f.readlines()[0].strip()
		else:
			offset="0"
		df=df.option("startingOffsets", """{"Hello-Kafka":{"0":"""+offset+"""}}""").load()
		newoffset=df.select(col("offset")).alias("offset").select("offset.*")
		newoffset=newoffset.agg(F.max("offset")).collect()[0]['max(offset)']
		print(df.count())
		with open("kafkaOffset.txt","w") as of:
			of.write(str(int(newoffset)-N))
		df=df.select(col("value").cast("string")).alias("csv").select("csv.*")
		#cols=["ts","te","td","sa","da","sp","dp","pr","flg","fwd","stos","ipkt","ibyt","opkt","obyt","in","out","sas","das","smk","dmk","dtos","dir", "nh","nhb","svln","dvln","ismc","odmc","idmc","osmc","mpls1","mpls2","mpls3","mpls4","mpls5","mpls6","mpls7","mpls8","mpls9","mpls10","cl","sl","al","ra","eng","exid","tr"]
		cols=['ts','te','sa','da','sp','dp',"features","anomalyScore"]
		colargs=[]
		for i,column in enumerate(cols):
			colargs.append("split(value,',')["+str(i)+"] as "+cols[i])
		df=df.selectExpr(*colargs)
		df=df.select('ts','te','sa','da','sp','dp',"features","anomalyScore")
		df=df.dropna()
		#df=df.limit(1000)
		runPipeline(df)


