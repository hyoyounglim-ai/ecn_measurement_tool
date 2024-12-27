
# Copyright 2021 Cable Television Laboratories, Inc. (CableLabs)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket, sys, struct, os, binascii
# from netaddr import IPNetwork, IPAddress
from ctypes import *

# changes byte order for some tcp header fields (ack, seq)
# needed for https://ctftime.org/task/8902
change_byte_order = False
def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


# print(int2ip(0xc0a80164)) # 192.168.1.100
# print(ip2int('10.0.0.1')) # 167772161



def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg) - 1, 2):
        w = msg[i] + (msg[i + 1] << 8)
        s = s + w

    if (len(msg) % 2 == 1):
        w = msg[-1]
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


"""
Construct an IP header.
For a TCP packet, only source and destination IPs need to be set.
source_ip = str IP of sender
dest_ip   = str IP of receiver
ihl       = Internet Header Length. Default is 5 (20 bytes).
ver       = IP version. default is 4
pid       = ID of the packet. So that split packets may be reassembled in order.
offs      = Fragment offset if any. default 1
ttl       = Time To Live for the packet. default 255
proto     = Protocol for contained packet. default is TCP.
"""


def construct_ip_header(source_ip, dest_ip, ihl=5, ver=4, tos=0, pid=0, offs=0, ttl=255, proto=socket.IPPROTO_TCP):
    ip_ihl = ihl
    ip_ver = ver
    ip_tos = tos
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = pid  # Id of this packet
    ip_frag_off = offs
    ip_ttl = ttl
    ip_proto = proto
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                            ip_check, ip_saddr, ip_daddr)
    # print(ip_header)
    header = struct.unpack('!BBHHHBBH4s4s', ip_header)
    # print('header: ', header)
    return ip_header


"""
Construct a TCP header.
source_ip = str IP of sender
dest_ip   = str IP of receiver
srcp      = source port number
dstp      = receiver port number
seq       = TCP sequence number: set a random number for first package and the ack number of previous received ACK package otherwise.
ackno     = TCP ack number: previous received seq + number of bytes received
flags     = TCP flags in an array with the structure [HS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN]
user_data = string with the data to send
doff      = data offset, default 0
wsize     = max window size for sender
urgptr    = Urgent pointer if URG flag is set
"""


def construct_tcp_header(source_ip, dest_ip, srcp, dstp, seq, ackno, flags, user_data="", doff=5, wsize=5840, urgptr=0):
    if change_byte_order:
        seq = socket.htonl(seq)
        ackno = socket.htonl(ackno)

    tcp_source = srcp  # source port
    tcp_dest = dstp  # destination port
    tcp_seq = seq
    tcp_ack_seq = ackno
    tcp_doff = doff
    # tcp flags
    # flags=[HS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN]
    tcp_fin = flags[8]
    tcp_syn = flags[7]
    tcp_rst = flags[6]
    tcp_psh = flags[5]
    tcp_ack = flags[4]
    tcp_urg = flags[3]
    tcp_window = socket.htons(wsize)  # maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = urgptr

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                             tcp_window, tcp_check, tcp_urg_ptr)
    # print(tcp_header)
    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    # print(user_data)
    tcp_length = len(tcp_header) + len(user_data)

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    # print(psh)
    psh = psh + tcp_header + user_data
    # print('psh : ', psh, ' tcp_header :', tcp_header, ' user_data :', user_data)
    tcp_check = checksum(psh)

    # make the tcp header again and fill the correct checksum
    tcp_header = struct.pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                             tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    return tcp_header

def construct_data_payload(magic, tos):
    payload = struct.pack('!HH', magic, tos)
    return payload


def construct_tcp_packet(ip_header, tcp_header, user_data=""):
    packet = ''
    # print(len(ip_header))
    # print(len(tcp_header))
    if user_data != "":
        packet = ip_header + tcp_header + user_data ## + bytes(99) + bytes(1) 
    else:
        packet = ip_header + tcp_header
    return packet


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("total_len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint),
        ("dst", c_uint)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        self.total_len = socket.htons(self.total_len)
        # TODO: need to htonl other fields!

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class TCP(Structure):
    _fields_ = [
        ("srcp", c_ushort),
        ("destp", c_ushort),
        ("seqno", c_uint),
        ("ackno", c_uint),
        ("flags", c_ushort),
        ("wsize", c_ushort),
        ("sum", c_ushort),
        ("urg", c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # readable port numbers
        self.src_port = socket.htons(self.srcp)
        self.dst_port = socket.htons(self.destp)

        # separate flags
        flagsi = socket.htons(self.flags)
        self.fin = flagsi & 1
        self.syn = (flagsi >> 1) & 1
        self.rst = (flagsi >> 2) & 1
        self.psh = (flagsi >> 3) & 1
        self.ack = (flagsi >> 4) & 1
        self.urg = (flagsi >> 5) & 1
        self.ece = (flagsi >> 6) & 1
        self.cwr = (flagsi >> 7) & 1
        self.hs = (flagsi >> 8) & 1
        self.data_offset = (flagsi >> 12) & 0xf
        self.header_len = self.data_offset * 4

        if change_byte_order:
            self.seq_no = self.seqno
            self.ack_no = self.ackno
        else:
            self.seq_no = socket.htonl(self.seqno)
            self.ack_no = socket.htonl(self.ackno)

        self.win_size = socket.htons(self.wsize)


class DATA(Structure):
    _fields_ = [
        ("magic", c_ubyte),
        ("send_tos", c_ubyte),
        ("expect_tos", c_ubyte)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    # def __init__(self, socket_buffer=None):
    #     # readable port numbers
    #     self.magic_num = socket.htons(self.magic)
    #     self.send_tos_num = socket.htons(self.send_tos)
    #     self.expect_tos_num = socket.htons(self.expect_tos)

