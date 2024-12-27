import os, sys, time
import glob
from datetime import date
import tarfile
from collections import Counter
from collections import defaultdict
import numpy as np
import json
from pprint import pprint
import operator
import csv
import matplotlib.pyplot as plt
import matplotlib as mtp
import argparse
import yaml
import bios
import re

home_dir = '/Users/hyoyounglim/Documents/Projects/ecn_data_analyzer'
data_dic = '/Users/hyoyounglim/Documents/DATA/server_ecn_measure'
# data_dic = '/Users/hyoyounglim/Documents/DATA/test'
# data_dic = '/Users/hyoyounglim/Documents/Projects/ecn_measurement_tool/traceroute'
original_list = '/Users/hyoyounglim/Documents/Projects/ecn_measurement_tool/websitelist/web_20000.txt'

if sys.argv[1] == '1':  #init
    result_dic = {} 
    result_dic['TOTAL'] = {}
    with open(original_list) as f:
        lines=[line.rstrip() for line in f]
    for line in lines:
        ranking = line.split(',')[0]
        domain_name = line.split(',')[1]
        result_dic['TOTAL'][domain_name] = 0

    result_dic['TOTAL']

    result_dic['SAE-ECN'] = {}  # or ECN-capable
    result_dic['SAE-ECN']['number'] = 0 
    result_dic['SAE-ECN']['domain_name'] = []

    result_dic['SAE-notECN'] = {}
    result_dic['SAE-notECN']['number'] = 0
    result_dic['SAE-notECN']['domain_name'] = []

    result_dic['notSAE-notECN'] = {}
    result_dic['notSAE-notECN']['number'] = 0
    result_dic['notSAE-notECN']['domain_name'] = []

    result_dic['Error'] = {}
    result_dic['Error']['number'] = 0
    result_dic['Error']['domain_name'] = []

    f = open(data_dic+"/result_dic.yaml", "w")
    yaml.dump(result_dic, f)
    f.close()
else: 
    result_dic = bios.read(data_dic+"/result_dic.yaml")

def checkKey(dict, key):
    # print(dict.keys())
    if key in dict.keys():
        return 1
    else:
        return 0

file_list = glob.glob(data_dic+'/result*.txt')
for onefile in file_list:
    with open(onefile) as f:
        lines=[line.rstrip() for line in f]
    filename_only = onefile.split('/')[6]
    filename = filename_only.split('_')
    # print(filename)
    print('[SAE-ECN] Total number of lines : ', len(lines))
    for line in lines:
        domain_name = line.split(',')[1]
        # print(domain_name)
        if 'www' in domain_name:
            domain_name = domain_name[4:]

        result_dic['TOTAL'][domain_name] = 1
        # if checkKey(result_dic['TOTAL'],domain_name) == 1:
        #     result_dic['TOTAL'][domain_name] = 1
        # else: 
        #     result_dic['TOTAL'][domain_name] = 1
            # print(domain_name, result_dic['TOTAL'][domain_name])

        if not(domain_name in result_dic['SAE-ECN']['domain_name']):
            result_dic['SAE-ECN']['domain_name'].append(domain_name)
            result_dic['SAE-ECN']['number'] +=1
        # else:
        #     print(domain_name)

file_list = glob.glob(data_dic+'/revise*.txt')
for onefile in file_list:
    with open(onefile) as f:
        lines=[line.rstrip() for line in f]
    filename_only = onefile.split('/')[6]
    filename = filename_only.split('_')
    # print(filename)
    print('[Revise] Total number of lines : ', len(lines))
    # Need to revist TODO: check the number of duplicated IPs 
    for line in lines:
        status = line.split(',')[0]
        domain_name = line.split(',')[1]

        if 'www' in domain_name:
            domain_name = domain_name[4:]

        result_dic['TOTAL'][domain_name] = 1
        # print(domain_name)
        if not(domain_name in result_dic['SAE-ECN']['domain_name']):
            if status == 'SAE-notECN' and not(domain_name in result_dic['SAE-notECN']['domain_name']):
                result_dic['SAE-notECN']['number'] += 1
                result_dic['SAE-notECN']['domain_name'].append(domain_name)
            elif status == 'notSAE-notECN' and not(domain_name in result_dic['notSAE-notECN']['domain_name']):
                result_dic['notSAE-notECN']['number'] += 1
                result_dic['notSAE-notECN']['domain_name'].append(domain_name)
            elif status == 'Error' and not(domain_name in result_dic['Error']['domain_name']):
                result_dic['Error']['number'] += 1
                result_dic['Error']['domain_name'].append(domain_name)

        # else:
        #     print(domain_name)
# print(result_dic['SAE-ECN']['domain_name'])
total = result_dic['SAE-ECN']['number']+result_dic['SAE-notECN']['number']+result_dic['notSAE-notECN']['number']
print(result_dic['SAE-ECN']['number'], result_dic['SAE-notECN']['number'], result_dic['notSAE-notECN']['number'], result_dic['Error']['number'])
print(result_dic['SAE-ECN']['number']+result_dic['SAE-notECN']['number'])

sum = 0
for key in result_dic['TOTAL'].keys(): 
    sum = sum + result_dic['TOTAL'][key]

print(sum)
print(total)

for name in result_dic['SAE-ECN']['domain_name']: 
    # print(name)
    try:
        result_dic['notSAE-notECN']['domain_name'].remove(name)
    except:
        a = 0
    try:
        result_dic['SAE-notECN']['domain_name'].remove(name)
    except:
        a = 0
    try:
        result_dic['Error']['domain_name'].remove(name)
    except:
        a = 0

for name in result_dic['SAE-notECN']['domain_name']: 
    # print(name)
    try:
        result_dic['notSAE-notECN']['domain_name'].remove(name)
    except:
        a = 0
    try:
        result_dic['Error']['domain_name'].remove(name)
    except:
        a = 0

for name in result_dic['notSAE-notECN']['domain_name']: 
    # print(name)
    try:
        result_dic['Error']['domain_name'].remove(name)
    except:
        a = 0

total = result_dic['SAE-ECN']['number']+result_dic['SAE-notECN']['number']+result_dic['notSAE-notECN']['number']
print(result_dic['SAE-ECN']['number'], result_dic['SAE-notECN']['number'], result_dic['notSAE-notECN']['number'], result_dic['Error']['number'])
print(result_dic['SAE-ECN']['number']+result_dic['SAE-notECN']['number'])

sum = 0
for key in result_dic['TOTAL'].keys(): 
    sum = sum + result_dic['TOTAL'][key]

print(sum)
print(total)

f = open(data_dic+"/result_dic.yaml", "w")
yaml.dump(result_dic, f)
f.close()



