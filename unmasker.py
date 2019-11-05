#!/home/lone/Documents/job_se/excel-masking/reqlibs/bin/python
import sys
import string
from io import StringIO
from struct import pack
import base64
import json
import argparse

import boto3
from botocore.exceptions import ClientError
import pandas as pd
from Crypto.Hash import MD5
from Crypto.Cipher import Blowfish
from Crypto import Random
from Crypto.Random import random

class Unmasker():

	def __init__(self):
		self.s3 = boto3.client('s3')

	def get_csv_from_s3(self,bucket_name,object_name,local_file_name):
		self.file_name=local_file_name
		self.s3.download_file(bucket_name,object_name,self.file_name)
		self.df=pd.read_csv(self.file_name)
	def get_log_from_s3(self,bucket_name,object_name,local_file_name):
		self.log_file_name=local_file_name
		self.s3.download_file(bucket_name,object_name,self.log_file_name)
		with open(self.log_file_name) as json_log_file:
			self.json_log=json.load(json_log_file)
	def unmask(self,columns):
		for column in columns:
			if(self.json_log[column]['mask_type']!='reversible_mask'):
				print("Sorry %s column was irreversibly masked"%(column))
			else:
				if(self.json_log[column]['cipher']=='blowfish_cbc'):
					key=self.json_log[column]['cipher_key']
					for i in range (0,len(self.df[column])):			
						bs = Blowfish.block_size
						self.df.loc[i,column]=base64.b64decode(self.df.loc[i,column].encode('utf8'))
						iv = self.df.loc[i,column][:bs]
						self.df.loc[i,column] = self.df.loc[i,column][bs:]
						cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
						msg = cipher.decrypt(self.df.loc[i,column])
						last_byte = msg[-1]
						self.df.loc[i,column] = msg[:- (last_byte if type(last_byte) is int else ord(last_byte))].decode('utf8')
					self.json_log.pop(column,None)

	def save_to_object(self):
		self.converted_fileobj=StringIO()
		self.df.to_csv(path_or_buf=self.converted_fileobj,index=False)
	
	def calculate_convertedfile_md5(self):
		self.md5=MD5.new(self.converted_fileobj.getvalue().encode('utf8')).hexdigest()
		self.json_log['md5']=self.md5

	def save_local(self):
		self.calculate_convertedfile_md5()
		self.masked_file_name=self.file_name.split('_md5_')[0]+'_md5_'+self.md5+'.'+self.file_name.split('.')[-1]
		self.log_filename=self.md5+'.json'
		self.json_log['masked_file_name']=self.masked_file_name
		with open(self.masked_file_name, 'w+') as masked_file:
			masked_file.write(self.converted_fileobj.getvalue())
		with open(self.log_filename,'w+') as logfile:
			json.dump(self.json_log,logfile)
		self.json_log['log_filename']=self.log_filename
		return 0

	def upload_to_s3(self,bucket):
		s3_client = boto3.client('s3')
		try:
			response = s3_client.upload_file(self.masked_file_name, bucket, self.masked_file_name)
		except ClientError as e:
			return (False,e)
		try:
			response = s3_client.upload_file(self.log_filename, 'masked-logstore', self.log_filename)
		except ClientError as e:
			return (False,e)
		print("The files unmasked file : %s is in bucket masked-filestore \nLogfile: %s is in bucket masked-logstore\n"%(self.masked_file_name,self.log_filename))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='CSV Masker')
	parser.add_argument('-um','--unmask' ,nargs='+',help='Names of columns that are to be unmasked masked.')
	parser.add_argument('-sb','--source_bucket',metavar=('source_bucket', 'prefixed_filename_s3'),nargs=2,help='Give bucket name Followed by prefixed objectname')
	args = parser.parse_args()
	
	unmask_plz=Unmasker()
	unmask_plz.get_csv_from_s3(bucket_name=args.source_bucket[0],object_name=args.source_bucket[1],local_file_name=args.source_bucket[1])
	log=args.source_bucket[1].split('_md5_')[1].split('.')[0]+'.json'
	unmask_plz.get_log_from_s3(bucket_name='masked-logstore',object_name=log,local_file_name=log)
	unmask_plz.unmask(args.unmask)
	unmask_plz.save_to_object()
	unmask_plz.save_local()
	unmask_plz.upload_to_s3('unmasked-filestore')
	