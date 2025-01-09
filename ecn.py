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
debug_file_name = 'ecnserver/debug_'+str(MyIP)+'.txt'

class Sniffer(threading.Thread):
    def  __init__(self, interface=None):
        global destip
        super().__init__()

        if interface is None:
            available_ifaces = get_if_list()
            default_iface = conf.iface
            print(f"[*] available interfaces: {available_ifaces}")
            print(f"[*] default interface: {default_iface}")
            
            self.interface = default_iface
        else:
            self.interface = interface

        self.seq = 0
        self.ack = 0
        self.lock = 0
        self.ecnon = 0
        self.flags = 0
        print('[**] init sniffer destip: ',destip, ' flags = ', self.flags, 'seq: ', self.seq, ' ack = ', self.ack, ' lock = ', self.lock, ' ecnon = ', self.ecnon)

        with open(debug_file_name, 'a') as f:
            f.write(f'[*] available interfaces: {available_ifaces}\n')
            f.write(f'[*] default interface: {default_iface}\n')
            f.write(f'[**] init sniffer destip: {destip}, flags = {self.flags}, seq: {self.seq}, ack = {self.ack}, lock = {self.lock}, ecnon = {self.ecnon}\n')

    def run(self):
        try:
            sniff(iface=self.interface, filter="tcp port 80", prn=self.print_packet, store=0)
        finally: 
            print('ended') 

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        if IP in packet and packet[IP].src == destip: #who-has or is-at
            print("\n=== TCP Packet Details ===")
            print(f"Source IP: {packet[IP].src}")
            print(f"Destination IP: {packet[IP].dst}")
            print(f"IP ToS: {packet[IP].tos:08b} (binary) = {packet[IP].tos}")

            if TCP in packet:
                print("\nTCP Details:")
                print(f"Source Port: {packet[TCP].sport}")
                print(f"Destination Port: {packet[TCP].dport}")
                print(f"Sequence Number: {packet[TCP].seq}")
                print(f"Acknowledgment: {packet[TCP].ack}")
                print(f"TCP Flags: {packet[TCP].flags}")
                print(f"Window Size: {packet[TCP].window}")
                
                # Print TCP options if they exist
                if packet[TCP].options:
                    print("TCP Options:", packet[TCP].options)

            ecn_bits = packet[IP].tos & 0xf
            tmp_flag = str(packet[TCP].flags)
            print("\nECN Details:")
            print(f"ECN Bits: {ecn_bits}")
            print(f"Current Flags State: {self.flags}")
            print(f"Current Flag: {tmp_flag}")

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
            print("========================\n")
            print("\nState Variables:")
            print(f"Lock: {self.lock}")
            print(f"ECN On: {self.ecnon}")
            print(f"Sequence: {self.seq}")
            print(f"Acknowledgment: {self.ack}")
            print("========================\n")
            print('[&&&&] flags: ', packet[TCP].flags, ' ecn = ', ecn_bits, ' payload = ', payload, ' seq = ', packet[TCP].seq, ' ack = ', packet[TCP].ack)
            print('[&&&&] sniffer destip: ',destip, ' flags = ', self.flags, 'seq: ', self.seq, ' ack = ', self.ack, ' lock = ', self.lock, ' ecnon = ', self.ecnon)
                
        with open(debug_file_name, 'a') as f:
            f.write("\n=== TCP Packet Details ===\n")
            f.write(f"Source IP: {packet[IP].src}\n")
            f.write(f"Destination IP: {packet[IP].dst}\n")
            f.write(f"IP ToS: {packet[IP].tos:08b} (binary) = {packet[IP].tos}\n")
            
            if TCP in packet:
                f.write("\nTCP Details:\n")
                f.write(f"Source Port: {packet[TCP].sport}\n")
                f.write(f"Destination Port: {packet[TCP].dport}\n")
                f.write(f"Sequence Number: {packet[TCP].seq}\n")
                f.write(f"Acknowledgment: {packet[TCP].ack}\n")
                f.write(f"TCP Flags: {packet[TCP].flags}\n")
                f.write(f"Window Size: {packet[TCP].window}\n")
                
                # Print TCP options if they exist
                if packet[TCP].options:
                    f.write("TCP Options: " + str(packet[TCP].options) + "\n")

            f.write("\nECN Details:\n")
            f.write(f"ECN Bits: {ecn_bits}\n")
            f.write(f"Current Flags State: {self.flags}\n")
            f.write(f"Current Flag: {tmp_flag}\n")

            f.write("\nState Variables:\n")
            f.write(f"Lock: {self.lock}\n")
            f.write(f"ECN On: {self.ecnon}\n")
            f.write(f"Sequence: {self.seq}\n")
            f.write(f"Acknowledgment: {self.ack}\n")

            f.write("\n========================\n")

            f.write('[&&&&] flags: ' + str(packet[TCP].flags) + ' ecn = ' + str(ecn_bits) + ' payload = ' + str(payload) + ' seq = ' + str(packet[TCP].seq) + ' ack = ' + str(packet[TCP].ack) + "\n")
            f.write('[&&&&] sniffer destip: ' + destip + ' flags = ' + str(self.flags) + ' seq: ' + str(self.seq) + ' ack = ' + str(self.ack) + ' lock = ' + str(self.lock) + ' ecnon = ' + str(self.ecnon) + "\n")

def run_one_ecn(domain_name):
    try:
        global destip
        destip = socket.gethostbyname(domain_name)
        ip_addr = destip
        dport = 80
        seqnum = randint(1, 4294967295)

        sniffer = Sniffer()
        with open(debug_file_name, 'a') as f:
            f.write(f"[*] Start sniffing... with {domain_name}\n")
        sniffer.start()

        time.sleep(2)

        syn = IP(dst=domain_name) / TCP(dport=dport, flags='SEC', seq=seqnum, options=[('MSS',1460)])
        syn_ack = sr1(syn, verbose=False, timeout=2)
        # print('domain_name: ', domain_name, 'flags: ', syn_ack[TCP].flags, ' tos = ', syn_ack[IP].tos)s
        sport=syn_ack[TCP].dport

        ACK = IP(dst=domain_name, tos = 2) / TCP(dport=dport, sport=sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')
        send(ACK, verbose=False)
        getStr = 'GET / HTTP/1.1\r\nHost:' + domain_name + '\r\nAccept-Encoding: gzip, deflate\r\n\r\n'
        request = IP(dst=domain_name, tos = 2) / TCP(dport=dport, sport=sport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')/getStr
        send(request, verbose=False)
        # reply = sniff(timeout=10,filter="tcp and port 80")

        time.sleep(1)

        pkt = IP(dst=domain_name) 
        FIN=pkt/TCP(sport=sport, dport=dport, flags="FA", seq=sniffer.ack, ack=sniffer.seq+1)
        FINACK=sr1(FIN, verbose=False, timeout=2)
        if FINACK != None :
            LASTACK=pkt/TCP(sport=sport, dport=dport, flags="A", seq=FINACK[TCP].ack, ack=FINACK[TCP].seq+1)
            send(LASTACK, verbose=False)
        
        if sniffer.ecnon == 1 and sniffer.flags == 1:
            with open(debug_file_name, 'a') as f:
                f.write(f"{domain_name} is ECN-capable\n")
            opened_file = open(result_file_name, 'a')
            opened_file.write(str('SAE-ECN')+','+ip_addr+','+domain_name+"\n") 
            opened_file.close()
            os.system("pkill -9 python3")
        elif sniffer.ecnon == 0 and sniffer.flags == 1:
            print(domain_name, " has bleaching path or misconfigure")
            try:
                opened_file = open(revise_file_name, 'a')
            except FileNotFoundError:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(revise_file_name), exist_ok=True)
                opened_file = open(revise_file_name, 'a')
            opened_file.write(str('SAE-notECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        elif sniffer.ecnon == 0 and sniffer.flags == 0:
            print(domain_name, " is not ECN-capable")
            try:
                opened_file = open(revise_file_name, 'a')
            except FileNotFoundError:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(revise_file_name), exist_ok=True)
                opened_file = open(revise_file_name, 'a')
            opened_file.write(str('notSAE-notECN')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
        else:
            print(domain_name, " is not ECN-capable")
            try:
                opened_file = open(revise_file_name, 'a')
            except FileNotFoundError:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(revise_file_name), exist_ok=True)
                opened_file = open(revise_file_name, 'a')
            opened_file.write(str('Error')+','+ip_addr+','+domain_name+"\n")
            opened_file.close()
            os.system("pkill -9 python3")
    except:
        print(domain_name, " doesn't exist")
        try:
            opened_file = open(revise_file_name, 'a')
        except FileNotFoundError:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(revise_file_name), exist_ok=True)
            opened_file = open(revise_file_name, 'a')
        opened_file.write(str('Error')+','+ip_addr+','+domain_name+"\n")
        opened_file.close()
        os.system("pkill -9 python3")


def main():

    domain_name= sys.argv[1]
    run_one_ecn(domain_name)

main()
