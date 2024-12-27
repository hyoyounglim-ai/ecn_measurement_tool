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
$ ./install.sh

# please don't forget to block RST packets
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# Check the ecn enable on the client side 
$ sysctl net.ipv4.tcp_ecn

#if the output is 1, it means ecn is enabled.

## Create files for web site list in websitelist dir
$ ./generate_list.sh

web_2000.txt    web_4000.txt    web_6000.txt    web_8000.txt    web_10000.txt   
web_12000.txt   web_14000.txt   web_16000.txt   web_18000.txt   web_20000.txt
......
web_5.txt

# test file generation
$ ./run_traceroute.sh websitelist/web_5.txt

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


# before running run.sh, please run a code with 5 servers only. 
$ sudo ./run_test.sh

# Run webserver testing using web site top 600000, will save the result on 'ecnserver' dir
$ sudo ./run.sh

# Do not run run.sh and run_traceroute.sh at the same time. 

# compress all data and send it to Hyoyoung 
$ tar -cvf traceroute.tar.gz traceroute/*
$ tar -cvf ecnserver.tar.gz ecnserver/*
```


