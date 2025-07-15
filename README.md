<div align="center" id="top"> 
  <img src="./image/app.png" alt="ECN_measurement_tool" width="50" height="50" />

  &#xa0; 

  <!-- <a href="https://ecn_measurement_tool.netlify.app">Demo</a> -->
</div>

<h1 align="center">ECN_measurement_tool</h1>

<h4 align="center"> 🚧  Ecn_measurement_tool 🚀  Under construction...  🚧 </h4> 

<!-- <h4 align="center"> -->
[About](#dart-about) | [Starting](#checkered_flag-starting) | [License](#memo-license) | [Author](https://github.com/limlynn) 
<!-- </h4>  -->


## :dart: About ##

This is a tool for testing ECN bits for the Internet. We can test various pathes using this tool. There are two functions we have. First one is checking ECN enabling on the web server using `ecn.py` and `ecn_www.py`. The other one is checking the localization of the ECN bleaching on the router using `traceroute_only.py`. Each code will work using simple scripts such as `run.sh` and `run_traceroute.sh `.

## :checkered_flag: Starting ##

Connect device with use tethering or tethering with phone(should connect only cellular service)
It will takes long time :hourglass:. So place device on the static location and run the code. 


<!-- token: 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 -->
```bash
# Clone this project
$ git clone <git_url>

# Access
$ cd ecn_measurement_tool

# Install dependencies
$ sudo ./install.sh

# please don't forget to block RST packets
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# 재전송 시도 횟수를 0으로 설정
sudo sysctl -w net.ipv4.tcp_retries1=0
sudo sysctl -w net.ipv4.tcp_retries2=0

# 재전송 타임아웃 값을 매우 크게 설정
sudo sysctl -w net.ipv4.tcp_retrans_collapse=0

# Check the ecn enable on the client side 
$ sysctl net.ipv4.tcp_ecn

$ sudo sysctl -w net.ipv4.tcp_ecn=1
#if the output is 1, it means ecn is enabled.

## Create files for web site list in websitelist dir
$ ./generate_list.sh

web_2000.txt    web_4000.txt    web_6000.txt    web_8000.txt    web_10000.txt   
web_12000.txt   web_14000.txt   web_16000.txt   web_18000.txt   web_20000.txt
......
web_5.txt

venv
# 가상환경 권장 방식
sudo apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate

# test file generation
$ ./run_traceroute.sh filelist_traceroute_2.txt

# check the results files
$ cat traceroute/<filename for each website>

# if the result looks like this, it means the traceroute testing is working well. 
172.17.0.1	0	64	1	192	0	1	1
<ip address of the router>	1	64	1	192	0	1	1
<ip address of the router>	1	64	1	192	0	1	1
no answer
<ip address of the router>	1	64	1	192	0	1	1
no answer
<ip address of the router>	1	64	1	192	0	1	1
<ip address of the router>	1	64	1	192	0	1	1
<ip address of the router>	1	64	1	192	0	1	1
...
no answer
no answer
no answer
no answer
no answer
no answer
no answer
no answer
no answer
no answer


# Run traceroute using web site top 20000, will save the result on `traceroute` dir : Using UDP packet
$ sudo ./run_traceroute.sh filelist_traceroute.txt

# copy crux website list to website dir
$ cp output.txt websitelist/
# Run traceroute using crux top list 
$ sudo ./run_traceroute.sh filelist_traceroute_with_crux.txt

# before running run.sh, please run a code with 5 servers only. 
$ sudo ./run_test.sh

# Run webserver testing using web site top 600000, will save the result on 'ecnserver' dir
$ sudo ./run.sh

# Do not run run.sh and run_traceroute.sh at the same time. 

# compress all data and send it to Hyoyoung 
$ tar -cvf traceroute.tar.gz traceroute/*
$ tar -cvf ecnserver.tar.gz ecnserver/*
```


## ECN

```bash
# Setup environment
$ ./setup_env.sh

# Run program
$ sudo ./ecn.py google.com
     

```


## SETUP ENVIRONMENT for cloudlab vm

```bash

# before setup the environment, please add ssh key to the server using scp from the host machine 
$ scp ~/.ssh/id_rsa <username>@<server_ip>:~/.ssh/id_rsa

# for example, if the server is jevousai@amd102.utah.cloudlab.us
$ scp ~/.ssh/id_rsa jevousai@amd102.utah.cloudlab.us:~/.ssh/id_rsa

# for download file from the server
$ scp jevousai@amd102.utah.cloudlab.us:~/ecn_measurement_tool/traceroute/traceroute_ip_list.txt .

# connect the server using ssh
$ ssh jevousai@amd102.utah.cloudlab.us

# after connect the server using ssh, sudo apt update
$ sudo apt update

# install git
$ sudo apt install git -y

# do permission for the ssh key
$ chmod 600 ~/.ssh/id_rsa

# clone the repository
$ git clone git@github.com:hyoyounglim-ai/ecn_measurement_tool.git

# install the dependencies
$ cd ecn_measurement_tool
$ sudo ./install.sh  

# please don't forget to block RST packets
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP  

# check the ecn enable on the client side 
$ sysctl net.ipv4.tcp_ecn

#if the output is 1, it means ecn is enabled.     

```





sudo ./venv/bin/python3 traceroute_only.py test.csv
nohup ./venv/bin/python3 traceroute_only.py ip_extracted_traceroute_ip_list_20250707.csv 

scp -i "aws-1.pem" ~/Project/ecn_measurement_tool/asn/asn_prefixes_sampled.csv ubuntu@ec2-3-106-225-6.ap-southeast-2.compute.amazonaws.com:~/ecn_measurement_tool/asn/

scp ~/Project/ecn_measurement_tool/asn/asn_prefixes_sampled.csv root@49.50.129.152:~/ecn_measurement_tool/asn/

pw: G5-U362ePnbrt

nohup python traceroute_from_prefix.py asn/asn_prefixes_sampled.csv 