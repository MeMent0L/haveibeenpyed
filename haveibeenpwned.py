#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Preparing the data

1) Download data
~$ wget https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-count-v8.7z

2) Checksum (compare with hash on haveibeenpwned website)
~$ sha1sum pwned-passwords-sha1-ordered-by-count-v8.7z

2) Unzip
~$ 7z e pwned-passwords-sha1-ordered-by-count-v8.7z

3) Separate the files with bash and save the distinct files tinto dedicated directory
~$ split -b 1000m pwned-passwords-sha1-ordered-by-count-v8.txt 

    File has to be split due to size and RAM requirement
    The file size here is 1G per file, it may be reduced if RAM is a constraint, e.g. with <12G RAM

Preparing the script

1) Update directory to the split files in line 41
2) Set your list of passwords to check in line 42
3) Run it!

"""

import pandas as pd
import numpy as np
import os
import regex as re
import hashlib
import gc
gc.collect()


### Inputs

os.chdir("/directory/where/the/split/pwned-passwords/files/are/saved")
pwd_list=["qwertz123456789","12345", "password1","Myownsupersecretpassword", "Myownothergreatpassword"]


### Scripts

def pwd_hash(pwd_list):
    pwd_hash_list=[]
    
    for pwd in pwd_list:
        #pwd_hash=os.system("echo -n " +pwd+ " | openssl sha1")
        pwd_hash=hashlib.sha1(pwd.encode()).hexdigest().upper()
        pwd_hash_list.append(pwd_hash)
    
    return pd.DataFrame(zip(pwd_list, pwd_hash_list),columns=["pwd","hashed_pwd"])

def data_prep(raw_data):
    raw_data=raw_data.replace("'","")
    split_data=raw_data.split(sep=":")
    clean_list=[]
    
    for item in split_data:
        detail=item.split(sep="\n")
        for each in detail:
            if len(each)==40:
                clean_list.append(each)
    
    return clean_list
    
def test_if_pwn(pwd_hash_df, hash_database):
    
    df=pd.DataFrame(hash_database, columns=["sha1_hash"])
    pwd_hash_list=list(pwd_hash_df["hashed_pwd"])    
    pwn_pwd_list=df[df.isin(pwd_hash_list)==True].dropna()
    
    if len(pwn_pwd_list)>0:
        return pwd_hash_df[pwd_hash_df["hashed_pwd"].isin(list(pwn_pwd_list["sha1_hash"]))]
    else:
        return []


### Analyze with hashed passwords files

final_list=[]
pwd_hash_df=pwd_hash(pwd_list)
path=str(os.getcwd())
for root, dirs, files in os.walk(path, topdown=False):
      
        for name in files:
            
            with open(name) as file:
                raw_data=file.read()
                       
            hash_database=data_prep(raw_data)
            output=test_if_pwn(pwd_hash_df, hash_database)            
            print("Found "+str(len(output))+" pwned passwords in file "+str(os.path.join(root, name)))
            
            for lines in output:   
                final_list.append(lines)            
print(final_list)
