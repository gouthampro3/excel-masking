#!/home/lone/Documents/job_se/excel-masking/reqlibs/bin/python
import sys
import string
from io import StringIO
from struct import pack
import base64
import json

import boto3
import pandas as pd
from Crypto.Hash import MD5
from Crypto.Cipher import Blowfish
from Crypto import Random
from Crypto.Random import random

class Masker():
	def __init__(self):
		self.s3 = boto3.client('s3')
		self.secret_key=self.get_secret()
		print(self.secret_key)
		self.json_log={}

	def get_from_s3(self,bucket_name,object_name,local_file_name):
		self.file_name=local_file_name
		self.s3.download_file(bucket_name,object_name,self.file_name)
		self.df=pd.read_csv(self.file_name)
	
	def get_secret(self):
		s=''
		for i in range(0,16):
			s=s+random.choice(string.printable)
		return MD5.new(data=s.encode('utf8')).hexdigest()

	def rev_mask(self,columns):
		for column in columns:
			for i in range (0,len(self.df[column])):
				if(isinstance(self.df[column][i], str)==False):
					self.df.loc[i,column]=str(self.df.loc[i,column])
				self.df.loc[i,column]=self.df.loc[i,column].encode('utf8')
				bs = Blowfish.block_size
				iv = Random.new().read(bs)
				cipher = Blowfish.new(self.secret_key, Blowfish.MODE_CBC, iv)
				plen = bs - divmod(len(self.df[column][i]),bs)[1]
				padding = [plen]*plen
				padding = pack('b'*plen, *padding)
				encrypted_string = iv + cipher.encrypt(self.df.loc[i,column]+ padding)
				self.df.loc[i,column] = (base64.b64encode(encrypted_string)).decode('utf8')
			self.json_log[column]={}
			self.json_log[column]['datatype']=str(self.df[column].dtype)
			self.json_log[column]['mask_type']='reversible_mask'
			self.json_log[column]['cipher']='blowfish_cbc'
			self.json_log[column]['cipher_key']=self.secret_key

	def irrev_mask(self,columns):
		for column in columns:
			for i in range (0,len(self.df[column])):
				salt = Random.new().read(16)
				if(isinstance(self.df[column][i], str)==False):
					self.df.loc[i,column]=str(self.df.loc[i,column])
				hash_cell=MD5.new(data=(salt+str(self.df[column][i]).encode('utf8')))
				self.df.loc[i,column] = hash_cell.hexdigest()
			self.json_log[column]={}
			self.json_log[column]['mask_type']='irreversible_mask'
			self.json_log[column]['hash_type']='MD5'
	
	def save_to_object(self):
		self.converted_fileobj=StringIO()
		self.df.to_csv(path_or_buf=self.converted_fileobj,index=False)
	
	def calculate_convertedfile_md5(self):
		self.md5=MD5.new(self.converted_fileobj.getvalue().encode('utf8')).hexdigest()
		self.json_log['md5']=self.md5

	def save_local(self):
		self.calculate_convertedfile_md5()
		self.masked_file_name=(self.file_name).split('.')[0]+'_md5_'+self.md5+'.'+(self.file_name).split('.')[1]
		self.json_log['masked_filename']=self.masked_file_name
		with open(self.masked_file_name, 'w+') as masked_file:
			masked_file.write(self.converted_fileobj.getvalue())
		with open(self.md5+'.json','w+') as logfile:
			json.dump(self.json_log,logfile)
		return 0

	def upload_to_s3(self,bucket):
		s3_client = boto3.client('s3')
		try:
			response = s3_client.upload_file(self.masked_file_name, bucket, self.masked_file_name)
		except ClientError as e:
			return (False,e)
		return (True,"Success")

if __name__ == '__main__':
	mask_plz=Masker()
	mask_plz.get_from_s3(bucket_name='unmasked-filestore',object_name='sample.csv',local_file_name='sample.csv')
	mask_plz.rev_mask(['Birthplace'])
	mask_plz.irrev_mask(['Code'])
	mask_plz.save_to_object()
	mask_plz.save_local()
	mask_plz.upload_to_s3('masked-filestore')