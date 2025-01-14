echo "Starting install.sh, if you need to put sudo, please sudo ./install.sh ";

apt update
apt install python3 -y
apt install python3-pip -y
apt install python3-pycurl -y
apt install libpcap0.8 libpcap0.8-dev tcpdump git -y
pip3 install psutil dnspython3 paramiko
pip3 install scapy sh yattag numpy argparse requests netaddr libpcap ipwhois 
pip3 install bios numpy yattag pyyaml matplotlib pandas ipfix
/sbin/sysctl -w net.ipv4.tcp_ecn=0
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

echo "Finished. Thank you." 