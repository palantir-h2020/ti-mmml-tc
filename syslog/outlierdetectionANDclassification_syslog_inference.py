from pyparsing import Word, alphas, Suppress, Combine, nums, string, Regex, Optional
import pandas as pd 
import argparse
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import matplotlib.pyplot as plt
import time
from sklearn.preprocessing import StandardScaler
from datetime import datetime
from time import mktime
from sklearn.ensemble import IsolationForest
import pickle
import collections
import warnings
from sklearn.ensemble import RandomForestClassifier
import json
from sklearn.preprocessing import LabelEncoder
warnings.filterwarnings("ignore")

	
class Parser(object):
    # log lines don't include the year, but if we don't provide one, datetime.strptime will assume 1900
    ASSUMED_YEAR = '2020'

    def __init__(self):
        ints = Word(nums)

        # priority
       # priority = Suppress("<") + ints + Suppress(">")

        # timestamp
        month = Word(string.ascii_uppercase, string.ascii_lowercase, exact=3)
        day   = ints
        hour  = Combine(ints + ":" + ints + ":" + ints)

        timestamp = month + day + hour
        # a parse action will convert this timestamp to a datetime
        timestamp.setParseAction(lambda t: datetime.strptime(Parser.ASSUMED_YEAR + ' ' + ' '.join(t), '%Y %b %d %H:%M:%S'))

        # hostname
        hostname = Word(alphas + nums + "_-.")

        # appname
        appname = Word(alphas + "/-_.()")("appname") + (Suppress("[") + ints("pid") + Suppress("]")) | (Word(alphas + "/-_.")("appname"))
        appname.setName("appname")

        # message
        message = Regex(".*")

        # pattern build
        # (add results names to make it easier to access parsed fields)
        self._pattern = timestamp("timestamp") + hostname("hostname") + Optional(appname) + Suppress(':') + message("message")

    def parse(self, line):
        parsed = self._pattern.parseString(line)
        # fill in keys that might not have been found in the input string
        # (this could have been done in a parse action too, then this method would
        # have just been a two-liner)
        for key in 'appname pid'.split():
            if key not in parsed:
                parsed[key] = ''
        return parsed.asDict()


def FeatureExtractor(df,features,time_windows):
	dff=df.copy()
	dff['datetime']=pd.to_datetime(dff['timestamp'],unit = 's')
	dff.index=dff['datetime']
	for i in features:
		#print(i)
		for j in time_windows:
			tmp_mean=dff[i].rolling(j,min_periods=1).mean().reset_index()[i]
			tmp_std=dff[i].rolling(j,min_periods=1).std().fillna(0).reset_index()[i]
			tmp_mean.index=df.index
			tmp_std.index=df.index
			df[f'{i}_mean_{j}'] = tmp_mean
			df[f'{i}_std_{j}'] = tmp_std
		
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Process some integers.')
	parser.add_argument('--inputfile', type=str, help='Input file.')
	parser.add_argument('--outliermodel', type=str, help='Outlier Model file.',default='isolationforest.pkl')
	parser.add_argument('--classifier', type=str, help='Classification Model file.',default='randomforestclassifier.pk')
	parser.add_argument('--vectorizerfile', type=str, help='Vectorizer file.',default='vectorizer_uncapped.pk')
	parser.add_argument('--labelencoder', type=str, help='Label encoder file.',default='labelencoder.pk')
	parser.add_argument('--cutoff', type=float, help='Cutoff point.',default=-0.45)
	parser.add_argument('--reload', dest='reload', action='store_true')
	parser.add_argument('--standardscalerfile', type=str, help='Standard scaler file.',default='standardscaler.pk') 
	parser.add_argument('--no-reload', dest='reload', action='store_false')
	parser.set_defaults(reload=False)
	parser.add_argument('--parse', dest='parse', action='store_true')
	parser.add_argument('--no-parse', dest='parse', action='store_false')
	parser.set_defaults(parse=True)
	#parser.add_argument('inputlabels', action='store', type=str, help='Input labels.')
	args = parser.parse_args()
	
	print('Parsing input file')
	parser=Parser()
	i=0
	if not args.reload:
		if args.parse:
			df = collections.OrderedDict()
			with open(args.inputfile) as file:
				for line in file: 
					# print(t)
					try:
						dict_new = parser.parse(line)
						df[i] = dict_new#df.append(dict_new, ignore_index=True)
						i+=1
					except:
						pass #print("Parsing error in line:", line)
			df=pd.DataFrame.from_dict(df,"index")
			with open(args.vectorizerfile,'rb') as pkl_file:
				v = pickle.load(pkl_file)
			x = v.transform(df['message'])
			#print(len(x.toarray()[0]))
			#print(len(v.get_feature_names()))
			df1 = pd.DataFrame(x.toarray(), columns=v.get_feature_names())
			df.drop('message', axis=1, inplace=True)
			res = pd.concat([df, df1], axis=1)
			res.to_csv('parsed.csv',index=False)

		df=pd.read_csv('parsed.csv')
		df=df.drop(["pid","appname","hostname"],axis=1)
		#labels=pd.read_csv(args.inputlabels,header=None,names=["label","secondarylabel"])
		#labels=labels.drop(labels.columns[1],axis=1)
		#labels.loc[labels['label'] != "0"]="1" #malicious=1
		#df=pd.concat([df,labels],axis=1)
		print('rows with nulls:',np.count_nonzero(df.isnull()))
		df=df.dropna()
		#print('columns:',df.columns)
		#print('head:',df.head())
		#df.label=pd.to_numeric(df.label)
		#print(df.dtypes)
		print('Scaling')
		df['timestamp'] =df['timestamp'].apply(lambda x: mktime(datetime.strptime(x,'%Y-%m-%d %H:%M:%S').timetuple()))
		#print('hasnan1',df.isnull().values.any())
		df=df.sort_values(by=['timestamp']).reset_index(drop=True)
		features=df.columns.tolist()
		features.remove("timestamp")
		#features.remove("label")
		print('Feature augmentation')
		durs=['10S','60S','10min']
		FeatureExtractor(df, features,durs)#, time_windows)
		#print('hasnan2',df.isnull().values.any())
		
		cols=df.columns
		#labels=df['label']
		with open(args.standardscalerfile,'rb') as pkl_file:
			scaler=pickle.load(pkl_file)
			df=scaler.transform(df)
		df = pd.DataFrame(df, columns=cols)
		#df['label']=labels
		df.to_csv('df.csv',index=False)
	else:
		df=pd.read_csv('df.csv')
	#labelsdf=df['label']
	#labels=labelsdf.values
	#print(labelsdf.value_counts())
	dataset=df.drop(['timestamp'],axis=1)#dataset=df.drop(['label','timestamp'],axis=1)
	
	#print('columns:',dataset.columns.tolist())
	#print('head:',dataset.head())
	print('Running Inference')
	with open(args.outliermodel,'rb') as pkl_file:
		isf = pickle.load(pkl_file)
	preds_isolation=isf.score_samples(dataset)
	cutoffindexes=np.where(preds_isolation<args.cutoff)
	
	with open(args.classifier,'rb') as pkl_file:
		rf = pickle.load(pkl_file)
	outliers=dataset.iloc[cutoffindexes]
	if outliers.shape[0]==0:
		print('No outliers detected (maybe increase cutoff point).')
	else:
		preds_rf=rf.predict(outliers)
		
		with open(args.labelencoder,'rb') as pkl_file:
			labelencoder = pickle.load(pkl_file)
		jsonObj=[]
		preds_probs=rf.predict_proba(outliers)
		#f=open("output.txt",'w')
		with open(args.inputfile) as file:
			for idx,line in enumerate(file):
				if idx in cutoffindexes[0]:# and preds_rf[np.where(idx==cutoffindexes[0])]!=0:
					predsindex=np.where(idx==cutoffindexes[0])
					jsonObj.append({"AnomalyDetectionSyslog":line,"Threat_Label":labelencoder.inverse_transform([int(preds_rf[predsindex])])[0],"Classification_Confidence":float(preds_probs[predsindex][0][preds_rf[predsindex]]),"Outlier_Score":float(preds_isolation[idx])})
					#f.write(line)
					#print('Outlier:',line)
		#f.close()
		with open('RESULTS/output.json', 'w') as outfile:
			json.dump(jsonObj, outfile)
		with open('RESULTS/output.json','r') as infile:
			with open('RESULTS/outputNoSpaces.json', 'w') as outfile:
				outfile.write(infile.readline().replace(" ","").replace("},{","}\n{").replace("[{","{").replace("}]","}"))
		print('Inference complete, check RESULTS/output.json')
