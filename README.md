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
$ git clone https://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@github.com/limlynn/ecn_measurement_tool.git


git remote add origin https://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@github.com/limlynn/measurement.git


# Access
$ cd ecn_measurement_tool

# Install dependencies
$ ./install.sh
# please don't forget to block RST packets
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

## Create files for web site list in websitelist dir
$ ./generate_list.sh

web_2000.txt    web_4000.txt    web_6000.txt    web_8000.txt    web_10000.txt   
web_12000.txt   web_14000.txt   web_16000.txt   web_18000.txt   web_20000.txt

# Run traceroute using web site top 20000, will save the result on `traceroute` dir : Using UDP packet
$ nohup sudo ./run_traceroute.sh filelist_traceroute.txt &

# Run webserver testing using web site top 600000, will save the result on 'ecnserver' dir
$ nohup sudo ./run.sh &

# Do not run run.sh and run_traceroute.sh at the same time. 


# compress all data and send it to Hyoyoung 
$ tar -cvf traceroute.tar.gz traceroute/*
$ tar -cvf ecnserver.tar.gz ecnserver/*
```

## :memo: License ##

<!-- This project is under license from MIT. For more details, see the [LICENSE](LICENSE.md) file. -->
Made with :heart: by <a href="https://github.com/limlynn" target="_blank">HL</a>

&#xa0;

# 이미지 빌드
docker build -t ecn-traceroute .

# 사용자 정의 네트워크 생성
docker network create --driver bridge ecn-network

# 컨테이너 실행 시 네트워크 연결
docker run --network ecn-network --cap-add=NET_ADMIN --cap-add=NET_RAW -it ecn-traceroute


# 네트워크 인터페이스 확인
ip addr show

# 라우팅 테이블 확인
route -n

# ECN 설정 확인
sysctl net.ipv4.tcp_ecn

# iptables 규칙 확인
iptables -L


<!-- # 컨테이너 실행 시 네트워크 연결
docker run --network ecn-network --cap-add=NET_ADMIN --cap-add=NET_RAW -it ecn-traceroute -->

# 컨테이너 실행 시 네트워크 연결
docker run --network ecn-network -v $(pwd):/app --cap-add=NET_ADMIN --cap-add=NET_RAW  --sysctl net.ipv4.tcp_ecn=0  --sysctl net.ipv4.ip_forward=1 -it ecn-traceroute

<!-- root@8c35a01b26ac:/app# sysctl net.ipv4.tcp_ecn
net.ipv4.tcp_ecn = 2
root@8c35a01b26ac:/app# sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 1
 -->

docker exec -it 8c35a01b26ac bash

<a href="#top">Back to top</a>
