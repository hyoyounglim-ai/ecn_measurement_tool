#!/usr/bin/env python3
import socket
import random
import time, os, sys
from requests import get
from os import path
from scapy.all import *
import threading 
from time import sleep
from random import *
import ctypes 
from datetime import date

MyIP = get('https://api.ipify.org').text
today = date.today() 
x="%.0f"%time.time()
start_time = time.time()
destip = '0.0.0.0'

result_file_name = 'ecnserver/result_'+str(MyIP)+'.txt'
revise_file_name = 'ecnserver/revise_'+str(MyIP)+'.txt'

class Sniffer(threading.Thread):
    def  __init__(self, interface="eno33"):
        global destip
        super().__init__()
        self.interface = interface
        self.seq = 0
        self.ack = 0
        self.lock = 0
        self.ecnon = 0
        self.flags = 0
        print('[**] init sniffer destip: ',destip, ' flags = ', self.flags, 'seq: ', self.seq, ' ack = ', self.ack, ' lock = ', self.lock, ' ecnon = ', self.ecnon)

    def run(self):
        try:
            sniff(iface=self.interface, filter="tcp port 80", prn=self.print_packet, store=0)
        finally: 
            print('ended') 

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        if IP in packet and packet[IP].src == destip: #who-has or is-at
            ecn_bits = packet[IP].tos & 0xf
            tmp_flag = str(packet[TCP].flags)
            # print(tmp_flag)
            if self.flags == 0:
                    if tmp_flag=='SAE' or tmp_flag=='SAEC' :
                        self.flags = 1
            try:
                payload = str(packet[TCP].payload.load).split('\\r\\n')[0]
                
                if self.lock == 0:
                    self.lock = 1
                    self.seq = packet[TCP].seq
                    self.ack = packet[TCP].ack
                
                if self.ecnon == 0 and ecn_bits == 2:
                    self.ecnon = 1
            except:
                payload = 'Hyoyoung'
            pid = os.getpid()
            print('[&&&&] flags: ', packet[TCP].flags, ' ecn = ', ecn_bits, ' payload = ', payload, ' seq = ', packet[TCP].seq, ' ack = ', packet[TCP].ack)
            print('[&&&&] sniffer destip: ',destip, ' flags = ', self.flags, 'seq: ', self.seq, ' ack = ', self.ack, ' lock = ', self.lock, ' ecnon = ', self.ecnon)

def run_ipv4(ip_addr, domain_name):
    dport = 80
    seqnum = randint(1, 4294967295)
    try:
        syn = IP(dst=ip_addr) / TCP(dport=dport, flags='SEC', seq=seqnum, options=[('MSS',1460)])
        syn_ack = sr1(syn, verbose=False, timeout=2)
        # print('domain_name: ', domain_name, 'flags: ', syn_ack[TCP].flags, ' tos = ', syn_ack[IP].tos)s
        sport=syn_ack[TCP].dport

        ACK = IP(dst=ip_addr, tos = 2) / TCP(dport=dport, sport=sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')
        send(ACK, verbose=False)
        getStr = 'GET / HTTP/1.1\r\nHost:' + domain_name + '\r\nAccept-Encoding: gzip, deflate\r\n\r\n'
        request = IP(dst=ip_addr, tos = 2) / TCP(dport=dport, sport=sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')/getStr
        send(request, verbose=False)
        # reply = sniff(timeout=10,filter="tcp and port 80")

        time.sleep(1)

        pkt = IP(dst=ip_addr) 
        FIN=pkt/TCP(sport=sport, dport=dport, flags="FA", seq=sniffer.ack, ack=sniffer.seq+1)
        FINACK=sr1(FIN, verbose=False, timeout=2)
        if FINACK != None :
            LASTACK=pkt/TCP(sport=sport, dport=dport, flags="A", seq=FINACK[TCP].ack, ack=FINACK[TCP].seq+1)
            send(LASTACK, verbose=False)
        
        if sniffer.ecnon == 1 and sniffer.flags == 1:
            print(domain_name, ip_addr, " is ECN-capable")
            opened_file = open(result_file_name, 'a')
            opened_file.write(str('SAE-ECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        elif sniffer.ecnon == 0 and sniffer.flags == 1:
            print(domain_name, ip_addr, " has bleaching path or misconfigure")
            opened_file = open(revise_file_name, 'a')
            opened_file.write(str('SAE-notECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        elif sniffer.ecnon == 0 and sniffer.flags == 0:
            print(domain_name, ip_addr, " is not ECN-capable")
            opened_file = open(revise_file_name, 'a')
            opened_file.write(str('notSAE-notECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        else:
            print(domain_name,ip_addr, " is not ECN-capable")
            opened_file = open(revise_file_name, 'a')
            opened_file.write(str('Error')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
    except:
        print(domain_name, ip_addr," doesn't exist")
        opened_file = open(revise_file_name, 'a')
        opened_file.write(str('Error')+','+ip_addr+','+domain_name+"\n")
        opened_file.close()
        os.system("pkill -9 python3")

def run_ipv6(ip_addr, domain_name):
    dport = 80
    seqnum = randint(1, 4294967295)
    try:
        syn = IPv6(dst=ip_addr) / TCP(dport=dport, flags='SEC', seq=seqnum, options=[('MSS',1460)])
        syn_ack = sr1(syn, verbose=False, timeout=2)
        # print('domain_name: ', domain_name, 'flags: ', syn_ack[TCP].flags, ' tos = ', syn_ack[IP].tos)s
        sport=syn_ack[TCP].dport

        ACK = IPv6(dst=ip_addr, tos = 2) / TCP(dport=dport, sport=sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')
        send(ACK, verbose=False)
        getStr = 'GET / HTTP/1.1\r\nHost:' + domain_name + '\r\nAccept-Encoding: gzip, deflate\r\n\r\n'
        request = IPv6(dst=ip_addr, tos = 2) / TCP(dport=dport, sport=sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')/getStr
        send(request, verbose=False)
        # reply = sniff(timeout=10,filter="tcp and port 80")

        time.sleep(1)

        pkt = IPv6(dst=ip_addr) 
        FIN=pkt/TCP(sport=sport, dport=dport, flags="FA", seq=sniffer.ack, ack=sniffer.seq+1)
        FINACK=sr1(FIN, verbose=False, timeout=2)
        if FINACK != None :
            LASTACK=pkt/TCP(sport=sport, dport=dport, flags="A", seq=FINACK[TCP].ack, ack=FINACK[TCP].seq+1)
            send(LASTACK, verbose=False)
        
        if sniffer.ecnon == 1 and sniffer.flags == 1:
            print(domain_name, ip_addr, " is ECN-capable")
            opened_file = open(result_file_name, 'a')
            opened_file.write(str('SAE-ECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        elif sniffer.ecnon == 0 and sniffer.flags == 1:
            print(domain_name, ip_addr, " has bleaching path or misconfigure")
            opened_file = open(revise_file_name, 'a')
            opened_file.write(str('SAE-notECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        elif sniffer.ecnon == 0 and sniffer.flags == 0:
            print(domain_name, ip_addr, " is not ECN-capable")
            opened_file = open(revise_file_name, 'a')
            opened_file.write(str('notSAE-notECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        else:
            print(domain_name,ip_addr, " is not ECN-capable")
            opened_file = open(revise_file_name, 'a')
            opened_file.write(str('Error')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
    except:
        print(domain_name, ip_addr," doesn't exist")
        opened_file = open(revise_file_name, 'a')
        opened_file.write(str('Error')+','+ip_addr+','+domain_name+"\n")
        opened_file.close()
        os.system("pkill -9 python3")

def run_one_ecn(ip_addr, domain_name):
    # try:
    global destip
    destip = ip_addr
    # destip = socket.gethostbyname(domain_name)
    dport = 80
    seqnum = randint(1, 4294967295)

    sniffer = Sniffer()
    print("[*] Start sniffing... with ", domain_name)
    sniffer.start()

    time.sleep(2)


    pattern = "^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$"
    match = re.match(pattern, destip)
    if (match):
        run_ipv4(destip, domain_name)
    else:
        os.system("pkill -9 python3")
        # run_ipv6(destip, domain_name)
    # except:
    #     print("Error", domain_name)

def main():

    line= sys.argv[1]
    domain_name = line.split(',')[1]
    ip_address = line.split(',')[2]
    print(domain_name, ip_address)
    run_one_ecn(ip_address, domain_name)

main()
