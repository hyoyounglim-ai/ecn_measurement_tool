#!/bin/bash
# ECN 설정
sysctl -w net.ipv4.tcp_ecn=0

# RST 패킷 차단
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# 인터페이스 설정
ip link set eth0 up
ethtool -K eth0 tx off sg off tso off ufo off gso off gro off lro off

# DNS 설정
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf