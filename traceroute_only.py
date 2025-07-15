#!/usr/bin/env python3
import socket
import struct
import tcppacket as rs
import random 
import time, os, sys
import argparse
from requests import get
from os import path
from scapy.all import *
import random
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
MyIP = get('https://api.ipify.org').text
from config import * 
import json
from ipwhois import IPWhois
from pprint import pprint
import numpy as np
import yaml
import bios

today = date.today() 
x="%.0f"%time.time()
start_time = time.time()
IP_LIST = sys.argv[1]

def is_valid_ip(ip):
    """IP 주소가 유효한지 검증하는 함수"""
    try:
        # IP 주소 형식 검증
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        
        return True
    except:
        return False

def main():
    logging.info('[ECN_SENDER] Start traceroute')
    with open(IP_LIST, "r") as f:
        list_of_ip=[x.strip().split(',') for x in f]
    
    # print(list_of_ip)

    for i in range(1, len(list_of_ip)):
        print(i, list_of_ip[i])
        traceroute_result = []
        
        # IP 주소 검증
        try:
            ip_addr = list_of_ip[i][2]
            
            # N/A, None, 빈 문자열 등 유효하지 않은 값 체크
            if not ip_addr or ip_addr.strip() == "" or ip_addr.upper() in ["N/A", "NULL", "NONE", "UNDEFINED"]:
                print(f"유효하지 않은 IP 주소 건너뛰기: {ip_addr}")
                continue
            
            # IP 주소 형식 검증
            if not is_valid_ip(ip_addr):
                print(f"잘못된 IP 주소 형식 건너뛰기: {ip_addr}")
                continue
                
        except (IndexError, AttributeError) as e:
            print(f"IP 주소 접근 오류: {e}")
            continue
        
        # print(ip_addr)
        if ip_addr != MyIP:
            init = 0
            destip = ip_addr
            filter="(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
            for tos in range(1, 2):
                bleaching = 0
                for j in range(0, 30):
                    res,unans = sr(IP(dst=destip, ttl=(j), tos=tos)/UDP(sport=53001, dport=80), timeout=0.3, filter=filter, verbose=0)
                    hops = j
                    if len(res) > 0:
                        try:
                            init+=1
                            sent_tos = res[0].query[IP].tos
                            icmp_tos = res[0].answer[IP].tos
                            icmp_src = res[0].answer[IP].src
                            icmp_ttl = res[0].answer[IP].ttl
                            iperror_tos = res[0].answer[IPerror].tos
                            icmp_ecn_bit = icmp_tos & 0x3
                            iperror_ecn_bit =  iperror_tos & 0x3
                            if (iperror_ecn_bit != tos):
                                bleaching +=1
                                print(icmp_src+"\t"+str(hops)+"\t"+str(icmp_ttl)+"\t"+str(sent_tos)+"\t"+str(icmp_tos)+"\t"+str(icmp_ecn_bit)+"\t"+str(iperror_tos)+"\t"+str(iperror_ecn_bit))
                            traceroute_result.append(str(icmp_src)+"\t"+str(hops)+"\t"+str(icmp_ttl)+"\t"+str(sent_tos)+"\t"+str(icmp_tos)+"\t"+str(icmp_ecn_bit)+"\t"+str(iperror_tos)+"\t"+str(iperror_ecn_bit)+"\n")
                        except:
                            traceroute_result.append("error\n")
                            continue
                    else:
                        traceroute_result.append("no answer\n")
            if init > 0:
                print('Saving the results : Traceroute to '+str(destip))
                File_name= 'Traceroute_Only_S_' + str(MyIP) +'_D_'+str(list_of_ip[i][0]+'_'+list_of_ip[i][2]+'_'+ip_addr)+'_'+str(today)+'_'+str(x)+'.txt'
                f_traceroute = open('traceroute/'+File_name, 'w')
                for line_traceroute in range(0, len(traceroute_result)):
                    f_traceroute.write(traceroute_result[line_traceroute])
                f_traceroute.close()
            else:
                print("no result with "+str(list_of_ip[i][2]))

main()

print("--- %s seconds ---" % (time.time() - start_time))