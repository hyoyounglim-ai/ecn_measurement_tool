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
import logging
import ipaddress
from datetime import date

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
MyIP = get('https://api.ipify.org').text

today = date.today()
x = "%.0f" % time.time()
start_time = time.time()

DEFAULT_IP_LIST = 'asn/asn_prefixes_sampled.csv'

def is_valid_ip(ip):
    """IP 주소가 유효한지 검증하는 함수"""
    try:
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

def get_random_ip_from_prefix(prefix):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            return str(net.network_address)
        return str(random.choice(hosts))
    except Exception as e:
        print(f"Prefix 파싱 오류: {prefix}, {e}")
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_list', nargs='?', default=DEFAULT_IP_LIST, help='CSV 파일 경로 (prefix, description, asn, country_code, country_name)')
    args = parser.parse_args()
    IP_LIST = args.ip_list

    logging.info('[ECN_SENDER] Start traceroute')
    list_of_ip = []
    with open(IP_LIST, "r") as f:
        next(f)  # 헤더 건너뜀
        for line in f:
            row = line.strip().split(',')
            if len(row) < 1:
                continue
            prefix = row[0].strip().strip('"')
            ip_addr = get_random_ip_from_prefix(prefix)
            # description, asn, country_code, country_name도 필요하면 row[1]~row[4] 사용
            list_of_ip.append([prefix, row[1] if len(row) > 1 else '', row[2] if len(row) > 2 else '', row[3] if len(row) > 3 else '', row[4] if len(row) > 4 else '', ip_addr])

    for i in range(len(list_of_ip)):
        print(i, list_of_ip[i])
        traceroute_result = []

        # IP 주소 검증
        try:
            ip_addr = list_of_ip[i][5]  # 6번째 열: 임의의 IP
            if not ip_addr or ip_addr.strip() == "" or ip_addr.upper() in ["N/A", "NULL", "NONE", "UNDEFINED"]:
                print(f"유효하지 않은 IP 주소 건너뛰기: {ip_addr}")
                continue
            if not is_valid_ip(ip_addr):
                print(f"잘못된 IP 주소 형식 건너뛰기: {ip_addr}")
                continue
        except (IndexError, AttributeError) as e:
            print(f"IP 주소 접근 오류: {e}")
            continue

        if ip_addr != MyIP:
            init = 0
            destip = ip_addr
            filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
            for tos in range(1, 2):
                bleaching = 0
                for j in range(0, 30):
                    res, unans = sr(IP(dst=destip, ttl=(j), tos=tos)/UDP(sport=53001, dport=80), timeout=0.3, filter=filter, verbose=0)
                    hops = j
                    if len(res) > 0:
                        try:
                            init += 1
                            sent_tos = res[0].query[IP].tos
                            icmp_tos = res[0].answer[IP].tos
                            icmp_src = res[0].answer[IP].src
                            icmp_ttl = res[0].answer[IP].ttl
                            iperror_tos = res[0].answer[IPerror].tos
                            icmp_ecn_bit = icmp_tos & 0x3
                            iperror_ecn_bit = iperror_tos & 0x3
                            if (iperror_ecn_bit != tos):
                                bleaching += 1
                                print(icmp_src+"\t"+str(hops)+"\t"+str(icmp_ttl)+"\t"+str(sent_tos)+"\t"+str(icmp_tos)+"\t"+str(icmp_ecn_bit)+"\t"+str(iperror_tos)+"\t"+str(iperror_ecn_bit))
                            traceroute_result.append(str(icmp_src)+"\t"+str(hops)+"\t"+str(icmp_ttl)+"\t"+str(sent_tos)+"\t"+str(icmp_tos)+"\t"+str(icmp_ecn_bit)+"\t"+str(iperror_tos)+"\t"+str(iperror_ecn_bit)+"\n")
                        except:
                            traceroute_result.append("error\n")
                            continue
                    else:
                        traceroute_result.append("no answer\n")
            if init > 0:
                print('Saving the results : Traceroute to '+str(destip))
                File_name = 'Traceroute_Only_S_' + str(MyIP) + '_D_' + str(ip_addr) + '_' + str(today) + '_' + str(x) + '.txt'
                output_dir = 'traceroute_prefix'
                os.makedirs(output_dir, exist_ok=True)
                with open(os.path.join(output_dir, File_name), 'w') as f_traceroute:
                    for line_traceroute in traceroute_result:
                        f_traceroute.write(line_traceroute)
            else:
                print("no result with "+str(ip_addr))

if __name__ == '__main__':
    main()
    print("--- %s seconds ---" % (time.time() - start_time))