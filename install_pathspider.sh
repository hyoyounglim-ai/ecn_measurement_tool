# sudo apt install libtrace-dev 
sudo apt install libldns-dev python3-dev python3-pip -y
sudo apt install libtrace-dev libldns-dev python3-dev python3-virtualenv -y
sudo apt-get install python3-pycurl -y

git clone https://github.com/nevil-brownlee/python-libtrace.git
pushd python-libtrace && sudo make install-py3 && popd

git clone https://github.com/mami-project/pathspider.git
pushd pathspider && \
    sudo pip3 install -r requirements.txt && \
    sudo pip3 install -r requirements_dev.txt && \
    sudo python3 setup.py develop && popd
pspdr test

# cat ~/ecn_measurement_tool/traceroute_ip_list.txt | sed -n '1, 300000p' >  examples/web_300000.txt
# cat examples/traceroute_ip_list.txt | sed -n '1, 300000p' >  examples/web_300000.txt
# sudo pspdr measure -i eno1 -w 100  --csv dnsresolv <examples/web_300000.txt > examples/web_300000.ndjson
# nohup sudo pspdr measure -i ens4 -w 100 ecn < examples/web_300000.ndjson > results.ndjson &
# nohup sudo pspdr measure -i eno33 ecn < examples/web_300000.ndjson > results.ndjson &

# scp -i ~/Documents/Projects/5g_measurement_auto/ssh_key/id_rsa hyoyoung@128.110.219.93:/users/hyoyoung/pathspider_original/examples/web_20000.ndjson ./examples



# sudo apt update
# sudo apt install python3-pip python3 python3-dev -y
# sudo apt install python3-pycurl -y
# sudo apt install libpcap0.8 libpcap0.8-dev tcpdump git net-tools vim traceroute iputils-ping -y
# sudo pip3 install psutil dnspython3
# sudo pip3 install scapy sh yattag numpy argparse requests netaddr libpcap ipwhois 
# sudo pip3 install bios numpy yattag pyyaml
# sudo pip3 install bios numpy yattag pyyaml matplotlib pandas ipfix
# sudo /sbin/sysctl -w net.ipv4.tcp_ecn=0
# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# sudo apt install libldns-dev -y
# sudo apt install libtrace-dev libldns-dev -y
# git clone https://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@github.com/limlynn/ecn_measurement_tool.git
# git clone https://github.com/nevil-brownlee/python-libtrace.git
# pushd python-libtrace && sudo make install-py3 && popd

# git clone https://github.com/mami-project/pathspider.git
# pushd pathspider && \
#     sudo pip3 install -r requirements.txt && \
#     sudo pip3 install -r requirements_dev.txt && \
#     sudo python3 setup.py develop && popd
