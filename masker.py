#!/home/lone/Documents/job_se/excel-masking/reqlibs/bin/python
import sys
import string
from io import StringIO
from io import BytesIO
from struct import pack
import base64
import json
import argparse
import random

import boto3
from botocore.exceptions import ClientError
import pandas as pd
from Crypto.Hash import MD5
from Crypto.Cipher import Blowfish
from Crypto import Random
from Crypto.Random import random

class Masker():
	def __init__(self):
		self.s3 = boto3.client('s3')
		self.secret_key=self.get_secret()
		self.json_log={}

	def get_file_from_s3(self,bucket_name,object_name,local_file_name):
		self.s3.download_file(bucket_name,object_name,local_file_name)
	
	def get_fo_from_s3(self,bucket,prefix,object_name):
		s3response = self.s3.get_object(Bucket=bucket, Key=prefix+object_name)
		response_str = s3response['Body'].read().decode('utf8')
		return response_str

	def get_secret(self):
		s=''
		for i in range(0,16):
			s=s+random.choice(string.printable)
		return MD5.new(data=s.encode('utf8')).hexdigest()

	def rev_mask(self,column):
		for i in range (0,len(self.df[column])):
			if(isinstance(self.df[column][i], str)==False):
				self.df.loc[i,column]=str(self.df.loc[i,column])
			self.df.loc[i,column]=self.df.loc[i,column].encode('utf8')
			bs = Blowfish.block_size
			iv = Random.new().read(bs)
			cipher = Blowfish.new(self.secret_key.encode('utf8'), Blowfish.MODE_CBC, iv)
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
		self.json_log[column]['essence']=False

	def irrev_mask(self,column):
		for i in range (0,len(self.df[column])):
			salt = Random.new().read(16)
			if(isinstance(self.df[column][i], str)==False):
				self.df.loc[i,column]=str(self.df.loc[i,column])
			hash_cell=MD5.new(data=(salt+str(self.df[column][i]).encode('utf8')))
			self.df.loc[i,column] = hash_cell.hexdigest()
		self.json_log[column]={}
		self.json_log[column]['mask_type']='irreversible_mask'
		self.json_log[column]['hash_type']='MD5'
		self.json_log[column]['essence']=False

	def maskcol(self,column,data_type,mask_type):
		self.json_log[column]={}
		self.json_log[column]['data_type']=data_type
		self.json_log[column]['mask_type']=mask_type
		self.json_log[column]['essence']=True
		self.json_log[column]['values']={}
		temp_dict={}
		col_len = len(str(len(self.df[column])))
		if(data_type=='int'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]= '0'*(col_len-len(str(i)))+str(i)
					temp_store=self.df.loc[i,column]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
					"""for future use?
					int_len=len(str(self.df.loc[i,column]))
					if(int_len==1):
						while(random_num in temp_dict.keys()):
							random_num = random.randint(0,9)
					else:
						while(random_num in temp_dict.keys()):
							random_num = random.randint(pow(10,int_len-1),int('9'*int_len))
					"""
		elif(data_type=='float'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]=str(i+round(random.uniform(0,1),len(str(self.df.loc[i,column]).split('.')[-1])))
					temp_store=self.df.loc[i,column]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]

		elif(data_type=='string'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]= column+'0'*(col_len-len(str(i)))+str(i)
					temp_store=self.df.loc[i,column]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]

		elif(data_type=='email'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					temp_dict[self.df.loc[i,column]]= column+str(i)+'@domain'+str(i)+'.xyz'
					temp_store=self.df.loc[i,column]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
			"""probably of no use
			elif(data_type=='gender'):
				for i in range(0,col_len):
					temp_dict[i]= random.sample(['Male','Female'],1)[0]
					self.df.loc[i,column]=temp_dict[i]
			"""

		elif(data_type=='phone_number'):
			for i in range(0,len(self.df[column])):
				if (self.df.loc[i,column] in temp_dict.keys()):
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
				else:
					num_int=0
					for j in self.df.loc[i,column]:
						if (j.isdigit()):
							num_int+=1
					randnum='0'*(num_int-len(str(i)))+str(i)
					randnum_format=''
					count=0
					for j in self.df.loc[i,column]:
						if (j.isdigit()):
							randnum_format+=randnum[count]
							count+=1
						else:
							randnum_format+=j
					temp_dict[self.df.loc[i,column]]= randnum_format
					temp_store=self.df.loc[i,column]
					if(mask_type=='reversible'):
						self.json_log[column]['values'][temp_dict[temp_store]]=self.df.loc[i,column]
					self.df.loc[i,column]=temp_dict[self.df.loc[i,column]]
		return 0

	def save_to_object(self):
		self.converted_fileobj=StringIO()
		self.df.to_csv(path_or_buf=self.converted_fileobj,index=False)
	
	def calculate_convertedfile_md5(self):
		self.md5=MD5.new(self.converted_fileobj.getvalue().encode('utf8')).hexdigest()
		self.json_log['md5']=self.md5

	def save_local(self):
		self.calculate_convertedfile_md5()
		self.masked_file_name=(self.manifest['filename']).split('.')[0]+'_md5_'+self.md5+'.'+(self.manifest['filename']).split('.')[1]
		self.log_filename=self.md5+'.json'
		self.json_log['masked_file_name']=self.masked_file_name
		with open(self.masked_file_name, 'w+') as masked_file:
			masked_file.write(self.converted_fileobj.getvalue())
		with open(self.log_filename,'w+') as logfile:
			json.dump(self.json_log,logfile)
		self.json_log['log_filename']=self.log_filename
		return 0

	def upload_to_s3(self,bucket):
		try:
			response = self.s3.upload_file(self.masked_file_name, bucket, 'masked_files/'+self.masked_file_name)
		except ClientError as e:
			return (False,e)
		try:
			response = self.s3.upload_file(self.log_filename, bucket, 'masked_files_logs/'+self.log_filename)
		except ClientError as e:
			return (False,e)
		print("The files masked file : %s is in bucket masked-filestore/masked_files \nLogfile: %s is in bucket masked-filestore/masked_files_logs store\n"%(self.masked_file_name,self.log_filename))

	def start_process(self):
		self.manifest=json.loads(self.get_fo_from_s3('unmasked-filestore','','manifest.json'))
		self.get_file_from_s3('unmasked-filestore',self.manifest['filename'],self.manifest['filename'])
		self.df=pd.read_csv(self.manifest['filename'])
		for column in self.manifest['columns']:
			if(self.manifest['columns'][column]['essence']==False):
				if(self.manifest['columns'][column]['mask_type']=='reversible'):
					self.rev_mask(column)			
				elif(self.manifest['columns'][column]['mask_type']=='irreversible'):
					self.irrev_mask(column)
			elif(self.manifest['columns'][column]['essence']==True):
				self.maskcol(column,self.manifest['columns'][column]['data_type'],self.manifest['columns'][column]['mask_type'])
		self.save_to_object()
		self.save_local()
		self.upload_to_s3('masked-filestore')
		self.s3.delete_objects(Bucket='unmasked-filestore',Delete={'Objects': [{'Key':self.manifest['filename'] },{'Key': 'manifest.json'}]})
if __name__ == '__main__':
	mask_plz=Masker()
	mask_plz.start_process()
	"""mask_plz.get_file_from_s3(bucket_name=args.source_bucket[0],object_name=args.source_bucket[1],local_file_name=args.source_bucket[2])
	mask_plz.rev_mask(args.revmask)
	mask_plz.irrev_mask(args.irrevmask)
	mask_plz.save_to_object()
	mask_plz.save_local()
	mask_plz.upload_to_s3('masked-filestore')"""