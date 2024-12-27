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

def main():
    logging.info('[ECN_SENDER] Start traceroute')
    with open(IP_LIST, "r") as f:
        list_of_ip=[x.strip().split(',') for x in f]

    for i in range(0, len(list_of_ip)):
        traceroute_result = []
        try:
            ip_addr = socket.gethostbyname(list_of_ip[i][1])
        except:
            print("No IP addr with web server :"+list_of_ip[i][1])
            continue
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
                File_name= 'Traceroute_Only_S_' + str(MyIP) +'_D_'+str(list_of_ip[i][0]+'_'+list_of_ip[i][1]+'_'+ip_addr)+'_'+str(today)+'_'+str(x)+'.txt'
                f_traceroute = open('traceroute/'+File_name, 'w')
                for line_traceroute in range(0, len(traceroute_result)):
                    f_traceroute.write(traceroute_result[line_traceroute])
                f_traceroute.close()
            else:
                print("no result with "+str(list_of_ip[i][1]))

main()

print("--- %s seconds ---" % (time.time() - start_time))