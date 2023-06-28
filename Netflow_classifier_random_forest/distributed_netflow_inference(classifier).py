from idsparsing import IDS_parser
import argparse
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import matplotlib.pyplot as plt
import time
from operator import truediv
from sklearn.preprocessing import StandardScaler
from pyspark.sql import functions as F
from pyspark.ml.linalg import Vectors, VectorUDT
import math
import traceback
from pyspark.ml.functions import vector_to_array
from kafka import KafkaProducer,KafkaConsumer
from pyspark.sql.functions import array_max,monotonically_increasing_id,split,expr,flatten
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
import requests
import os
from pyspark.sql.window import Window
from pyspark.ml.feature import StandardScaler,VectorAssembler
import collections
import warnings
from pyspark.ml.feature import StringIndexer,VectorIndexer,IndexToString,StringIndexerModel
import ipaddress
from pyspark.ml.classification import RandomForestClassifier
import json
from kafka import TopicPartition
from sklearn.preprocessing import LabelEncoder
warnings.filterwarnings("ignore")
from pyspark.sql import SparkSession
from pyspark.sql.functions import col
import threading

TENANT_ID = os.environ['TENANT_ID']
spark = SparkSession.builder.getOrCreate()
spark.sparkContext.setLogLevel('ERROR')

def partitioner(key_bytes, all_partitions, available_partitions):
	return PARTITION

alertCache={}	
def clearCache():
	global alertCache
	t=time.time()
	for key in alertCache.copy():
		if t-alertCache[key]>600:
			del alertCache[key]
producer = KafkaProducer(bootstrap_servers='10.101.41.255:9092',partitioner=partitioner) 
def runPipeline(df):
	global producer,alertCache
	print('Parsing input stream')
	#df=batch_df
	if df.count()==0:
		return
	print('shape',df.count())
	#df=df.filter(df.IFORESTFEATUREVECTOR.isNotNull())
	#print('shape',df.count())
	#df.select("MIDASNAME","MIDASSCORE","MIDASISOUTLIER","GANOMALYNAME","GANOMALYFEATUREVECTOR","GANOMALYSCORE","GANOMALYISOUTLIER","IFORESTNAME","IFORESTFEATUREVECTOR","IFORESTSCORE","IFORESTISOUTLIER","AENAME","AEFEATUREVECTOR","AESCORE","AEISOUTLIER").show(5)
	
	#df=df.filter((df.IFORESTFEATUREVECTOR != "\"[]\"") | (df.AEFEATUREVECTOR != "\"[]\""))
	#outlierModels=["IFOREST","AE"]
	#arraytovector = F.udf(lambda vs: Vectors.dense(vs), VectorUDT())
	#for outlierModel in outlierModels:
	try:
		#df=df.filter(col(outlierModel+"FEATUREVECTOR")!="\"[]\"")
		if df.count()==0:
			return#continue
		#df=df.withColumn("features", split(expr("rtrim(']\"', ltrim('\"[', "+outlierModel+"FEATUREVECTOR))"), ",")).withColumn("features", expr("""transform(features, x -> split(rtrim(']\"', ltrim('\"[', x)), ","))""")).withColumn("features", flatten(col("features")).cast("array<float>")).withColumn("features", arraytovector(col("features")))
		vecAssembler = VectorAssembler(inputCols=['ppf0', 'ppf1', 'ppf2', 'ppf3', 'ppf4', 'ppf5', 'ppf6', 'ppf7', 'ppf8', 'ppf9', 'ppf10', 'ppf11', 'ppf12', 'ppf13', 'ppf14', 'ppf15', 'ppf16', 'ppf17', 'ppf18', 'ppf19', 'ppf20', 'ppf21', 'ppf22', 'ppf23', 'ppf24', 'ppf25', 'ppf26', 'ppf27', 'ppf28', 'ppf29', 'ppf30', 'ppf31', 'ppf32'], outputCol="features")
		for col_name in ['ppf0', 'ppf1', 'ppf2', 'ppf3', 'ppf4', 'ppf5', 'ppf6', 'ppf7', 'ppf8', 'ppf9', 'ppf10', 'ppf11', 'ppf12', 'ppf13', 'ppf14', 'ppf15', 'ppf16', 'ppf17', 'ppf18', 'ppf19', 'ppf20', 'ppf21', 'ppf22', 'ppf23', 'ppf24', 'ppf25', 'ppf26', 'ppf27', 'ppf28', 'ppf29', 'ppf30', 'ppf31', 'ppf32']:
			df=df.withColumn(col_name,col(col_name).cast('float'))
		df=vecAssembler.transform(df)
		df.select("features").show(5)
		#if df.features.isNull():
			#continue
		#print(df.count())
		print('Running Inference')
		model=PipelineModel.load('spark_netflow_pickled_files/randomforestpipeline')
		predictions = model.transform(df)
		print(df.columns)
		print(predictions.columns)
		predictions=predictions.withColumn("probability",array_max(vector_to_array("probability")))
		predictions=predictions.select('ts', 'te', 'td', 'sa', 'da', 'sp', 'dp', 'pr', 'flg', 'stos', 'ipkt','ibyt',"predictedLabel","probability","MIDASSCORE","MIDASISOUTLIER","AESCORE","AEISOUTLIER","GANOMALYSCORE","GANOMALYISOUTLIER","IFORESTSCORE","IFORESTISOUTLIER","ZEEKFLOWSCORE","ZEEKFLOWISOUTLIER")
		#predictions.show(5)
		predictions=predictions.toPandas()
		idxes=predictions.index.tolist()
		clearCache()
		for i,idx in enumerate(idxes):
			dfentry=predictions.iloc[idx]
			predlabel="Botnet" if dfentry.predictedLabel!='Benign' else 'Benign'
			saReq=requests.post('http://10.101.41.42:8100/deanonymize',json={'IpAddr':dfentry.sa}).json()
			daReq=requests.post('http://10.101.41.42:8100/deanonymize',json={'IpAddr':dfentry.da}).json()
			#print('sa',saReq)
			#print('da',daReq)
			sa=dfentry.sa if 'error' in saReq.keys() else saReq['obfuscatedIp']
			da=dfentry.da if 'error' in daReq.keys() else daReq['obfuscatedIp']
			cacheTuple1=(sa,da)#,dfentry.predictedLabel)
			cacheTuple2=(da,sa)#,dfentry.predictedLabel)
			cacheKeys=alertCache.keys()
			if cacheTuple1 in cacheKeys or cacheTuple2 in cacheKeys or dfentry.predictedLabel=="Benign":
				continue
			jsonObj={"Threat_Finding":{"Time_Start":dfentry.ts,"Time_End":dfentry.te,"Time_Duration":dfentry.td,"Source_Address":sa,"Destination_Address":da,"Source_Port":int(dfentry.sp),"Destination_Port":int(dfentry.dp),"Protocol":dfentry.pr,"Flag":dfentry.flg,"Soure_tos":int(float(dfentry.stos)),"Input_packets":int(dfentry.ipkt),"Input_bytes":int(dfentry.ibyt)},"Threat_Label":dfentry.predictedLabel,"Threat_Category":predlabel,"Classification_Confidence":float(dfentry.probability),"Outlier_Score":float(dfentry['ZEEKFLOWSCORE']),"MITRE_ATT&CK_Classification": [],"MITRE_ATT&CK_Knowledge_Base": "Enterprise 12.1"}
			if (sa=="10.101.41.60" and da=="192.168.50.11") or (sa=="192.168.50.11" and da=="10.101.41.60"):
				print(json.dumps(jsonObj).encode('utf-8'))
				producer.send('ti.threat_findings_netflow', json.dumps(jsonObj).encode('utf-8'))
				#alertCache[(sa,da,dfentry.predictedLabel)]=time.time()
				alertCache[(sa,da)]=time.time()
	except:
		print(traceback.format_exc())
	
def crypto():
	print("CRYPTO THREAD STARTED========")
	consumer = KafkaConsumer(bootstrap_servers=['10.101.41.255:9092'])
	crypto_input_topic = os.getenv('KAFKA_TOPIC_IN_CDS', 'netflow-crypto-prediction')
	consumer.assign([TopicPartition(crypto_input_topic,int(PARTITION))])
	#consumer.assign([TopicPartition('netflow-crypto-prediction',int(PARTITION))])
	for message in consumer:
		print('Crypto message',message)
		message=message.value.decode("utf-8").split(',')
		if float(message[-1])>0.7:
			saReq=requests.post('http://10.101.41.42:8100/deanonymize',json={'IpAddr':message[3]}).json()
			daReq=requests.post('http://10.101.41.42:8100/deanonymize',json={'IpAddr':message[4]}).json()
			#print('sa',saReq)
			#print('da',daReq)
			sa=message[3] if 'error' in saReq.keys() else saReq['obfuscatedIp']
			da=message[4] if 'error' in daReq.keys() else daReq['obfuscatedIp']
			cacheTuple1=(sa,da)#,dfentry.predictedLabel)
			cacheTuple2=(da,sa)#,dfentry.predictedLabel)
			cacheKeys=alertCache.keys()
			if cacheTuple1 in cacheKeys or cacheTuple2 in cacheKeys:
				continue
			jsonObj={"Threat_Finding":{"Time_Start":message[0],"Time_End":message[1],"Time_Duration":message[2],"Source_Address":message[3],"Destination_Address":message[4],"Source_Port":int(message[5]),"Destination_Port":int(message[6]),"Protocol":message[7],"Flag":message[8],"Soure_tos":int(message[9]),"Input_packets":int(message[10]),"Input_bytes":int(message[11])},"Threat_Label":message[-3],"Threat_Category":message[-2],"Classification_Confidence":float(message[-1]),"Outlier_Score":float(message[-1]),"MITRE_ATT&CK_Classification": [],"MITRE_ATT&CK_Knowledge_Base": "Enterprise 12.1"}
			print('Crypto threat detected',json.dumps(jsonObj).encode('utf-8'))
			producer.send('ti.threat_findings_netflow', json.dumps(jsonObj).encode('utf-8'))
			alertCache[(sa,da)]=time.time()
	
if __name__ == "__main__":
	global PARTITION
	multitenancy_service_url = os.getenv('MULTITENANCY_SERVICE_URL', 'http://tenant-api-service.ti-dcp:6000/api/partition/')
	PARTITION=requests.get(multitenancy_service_url+str(TENANT_ID)).json()['partition']	
	#PARTITION=requests.get('http://tenant-api-service.ti-dcp:6000/api/partition/'+str(TENANT_ID)).json()['partition']	
	ids_thread=threading.Thread(target=IDS_parser.main)
	crypto_thread=threading.Thread(target=crypto)
	ids_thread.start()
	crypto_thread.start()
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('--cutoff', type=float, help='Cutoff point.',default=0.5)
	args = parser.parse_args()
	
	offset="0"
	N=0
	while True:
		df = spark.read.format("kafka").option("kafka.bootstrap.servers", "10.101.41.255:9092").option("assign", """{"netflow-ad-out":["""+str(PARTITION)+"""]}""").option("failOnDataLoss","false")
		if os.path.exists("kafkaOffset.txt"):
			f=open("kafkaOffset.txt")
			offset=str(int(f.readlines()[0].strip())+1)
		else:
			offset="0"
		df=df.option("startingOffsets", """{"netflow-ad-out":{"""+"\""+str(PARTITION)+"\""+""":"""+offset+"""}}""").load()
		newoffset=df.select(col("offset")).alias("offset").select("offset.*")
		newoffset=newoffset.agg(F.max("offset")).collect()[0]['max(offset)']
		print(df.count())
		if newoffset==int(offset)-1 or newoffset is None:
			continue
		with open("kafkaOffset.txt","w") as of:
			if int(newoffset)-N<0:
				of.write("0")
			else:
				of.write(str(int(newoffset)-N))
		df=df.select(col("value").cast("string")).alias("csv").select("csv.*")
		#print(df.select('value').collect())
		#cols=["ts","te","td","sa","da","sp","dp","pr","flg","fwd","stos","ipkt","ibyt","opkt","obyt","in","out","sas","das","smk","dmk","dtos","dir","nh","nhb","svln","dvln","ismc","odmc","idmc","osmc","mpls1","mpls2","mpls3","mpls4","mpls5","mpls6","mpls7","mpls8","mpls9","mpls10","cl","sl","al","ra","eng","exid","tr","tpkt","tbyt","cp","prtcp","prudp","pricmp","prigmp","prother","flga","flgs","flgf","flgr","flgp","flgu","MIDASNAME","MIDASFEATUREVECTOR","MIDASSCORE","MIDASISOUTLIER","GANOMALYNAME","GANOMALYFEATUREVECTOR","GANOMALYSCORE","GANOMALYISOUTLIER","IFORESTNAME","IFORESTFEATUREVECTOR","IFORESTSCORE","IFORESTISOUTLIER","AENAME","AEFEATUREVECTOR","AESCORE","AEISOUTLIER"]
		cols=["ts","te","td","sa","da","sp","dp","pr","flg","stos","ipkt","ibyt","MIDASSCORE","MIDASISOUTLIER","AESCORE","AEISOUTLIER","GANOMALYSCORE","GANOMALYISOUTLIER","IFORESTSCORE","IFORESTISOUTLIER","ZEEKFLOWSCORE","ZEEKFLOWISOUTLIER",'ppf0', 'ppf1', 'ppf2', 'ppf3', 'ppf4', 'ppf5', 'ppf6', 'ppf7', 'ppf8', 'ppf9', 'ppf10', 'ppf11', 'ppf12', 'ppf13', 'ppf14', 'ppf15', 'ppf16', 'ppf17', 'ppf18', 'ppf19', 'ppf20', 'ppf21', 'ppf22', 'ppf23', 'ppf24', 'ppf25', 'ppf26', 'ppf27', 'ppf28', 'ppf29', 'ppf30', 'ppf31', 'ppf32']
		colargs=[]
		for i,column in enumerate(cols):
			#colargs.append("split(value,',(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)')["+str(i)+"] as "+cols[i])
			colargs.append("split(value,',')["+str(i)+"] as "+cols[i])
		df=df.selectExpr(*colargs)
		#df=df.select('ts', 'te', 'td', 'sa', 'da', 'sp', 'dp', 'pr', 'flg', 'stos', 'ipkt','ibyt',"MIDASNAME","MIDASSCORE","MIDASISOUTLIER","GANOMALYNAME","GANOMALYFEATUREVECTOR","GANOMALYSCORE","GANOMALYISOUTLIER","IFORESTNAME","IFORESTFEATUREVECTOR","IFORESTSCORE","IFORESTISOUTLIER","AENAME","AEFEATUREVECTOR","AESCORE","AEISOUTLIER")
		df=df.select("ts","te","td","sa","da","sp","dp","pr","flg","stos","ipkt","ibyt","MIDASSCORE","MIDASISOUTLIER","AESCORE","AEISOUTLIER","GANOMALYSCORE","GANOMALYISOUTLIER","IFORESTSCORE","IFORESTISOUTLIER","ZEEKFLOWSCORE","ZEEKFLOWISOUTLIER",'ppf0', 'ppf1', 'ppf2', 'ppf3', 'ppf4', 'ppf5', 'ppf6', 'ppf7', 'ppf8', 'ppf9', 'ppf10', 'ppf11', 'ppf12', 'ppf13', 'ppf14', 'ppf15', 'ppf16', 'ppf17', 'ppf18', 'ppf19', 'ppf20', 'ppf21', 'ppf22', 'ppf23', 'ppf24', 'ppf25', 'ppf26', 'ppf27', 'ppf28', 'ppf29', 'ppf30', 'ppf31', 'ppf32')
		df=df.dropna()
		#df=df.limit(1000)
		runPipeline(df)


