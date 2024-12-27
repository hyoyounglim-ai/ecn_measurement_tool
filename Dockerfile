FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iputils-ping \
    tcpdump \
    curl \
    vim \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir \
    scapy \
    requests \
    ipwhois \
    numpy \
    pyyaml \
    bios

# Install network tools
RUN apt-get update && apt-get install -y \
    iproute2 \
    net-tools \
    iptables \
    ethtool \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Network configuration script
COPY network-setup.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/network-setup.sh

# Create working directory
WORKDIR /app

# Copy your files
COPY config.py .
COPY traceroute_only.py .
COPY run_traceroute.sh .
COPY ecn.py .
COPY ecn_www.py .
COPY tcppacket.py .
COPY timeout.py .
COPY traceroute_w_IP.py .
COPY generate_list.sh .
COPY install.sh .
COPY traceroute_ip_list.txt . 
COPY filelist_server.txt .
COPY filelist_server_test.txt .
COPY filelist_traceroute.txt .
COPY filelist_traceroute_2.txt .

# # Make scripts executable
RUN chmod +x *.sh *.py

# Create traceroute directory
RUN mkdir traceroute

ENTRYPOINT ["/bin/bash"]