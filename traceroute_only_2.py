#!/usr/bin/env python3

import socket
import time
import sys
import logging
from datetime import date
from requests import get
from pathlib import Path
from scapy.all import IP, UDP, IPerror, sr
from typing import List, Tuple

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ECNTraceRoute:
    def __init__(self):
        self.today = date.today()
        self.timestamp = "%.0f" % time.time()
        try:
            self.my_ip = get('https://api.ipify.org').text
        except Exception as e:
            logger.error(f"Failed to get public IP: {e}")
            self.my_ip = "unknown"
        
        # 상수 정의
        self.MAX_HOPS = 30
        self.TIMEOUT = 0.5
        self.UDP_SPORT = 53001
        self.UDP_DPORT = 80
        self.ICMP_FILTER = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"

    def resolve_hostname(self, hostname: str) -> str:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror as e:
            logger.error(f"Failed to resolve hostname {hostname}: {e}")
            return None

    def process_trace_response(self, res) -> Tuple[str, str]:
        try:
            sent_tos = res[0].query[IP].tos
            icmp_tos = res[0].answer[IP].tos
            icmp_src = res[0].answer[IP].src
            icmp_ttl = res[0].answer[IP].ttl
            iperror_tos = res[0].answer[IPerror].tos
            icmp_ecn_bit = icmp_tos & 0x3
            iperror_ecn_bit = iperror_tos & 0x3
            
            result = f"{icmp_src}\t{icmp_ttl}\t{sent_tos}\t{icmp_tos}\t{icmp_ecn_bit}\t{iperror_tos}\t{iperror_ecn_bit}\n"
            return result, iperror_ecn_bit
        except Exception as e:
            logger.error(f"Error processing trace response: {e}")
            return "error\n", None

    def trace_route(self, dest_ip: str, hostname: str, identifier: str):
        logger.info(f'Starting traceroute to {dest_ip}')
        traceroute_result = []
        init = 0

        for tos in range(1, 2):
            bleaching = 0
            for hop in range(self.MAX_HOPS):
                res, _ = sr(
                    IP(dst=dest_ip, ttl=hop, tos=tos)/UDP(sport=self.UDP_SPORT, dport=self.UDP_DPORT),
                    timeout=self.TIMEOUT,
                    filter=self.ICMP_FILTER,
                    verbose=0
                )

                if res:
                    init += 1
                    result, iperror_ecn_bit = self.process_trace_response(res)
                    traceroute_result.append(result)
                    
                    if iperror_ecn_bit is not None and iperror_ecn_bit != tos:
                        bleaching += 1
                        logger.info(f"ECN bleaching detected at hop {hop}")
                else:
                    traceroute_result.append("no answer\n")

        if init > 0:
            self.save_results(dest_ip, hostname, identifier, traceroute_result)
        else:
            logger.warning(f"No results for {hostname}")

    def save_results(self, dest_ip: str, hostname: str, identifier: str, results: List[str]):
        output_dir = Path('traceroute')
        output_dir.mkdir(exist_ok=True)
        
        filename = f'Traceroute_Only_S_{self.my_ip}_D_{identifier}_{hostname}_{dest_ip}_{self.today}_{self.timestamp}.txt'
        output_path = output_dir / filename
        
        try:
            with output_path.open('w') as f:
                f.writelines(results)
            logger.info(f'Results saved to {output_path}')
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

def main():
    if len(sys.argv) != 2:
        logger.error("Usage: python3 traceroute_only.py IP_LIST_FILE")
        sys.exit(1)

    ip_list_file = sys.argv[1]
    tracer = ECNTraceRoute()
    start_time = time.time()

    try:
        with open(ip_list_file, "r") as f:
            for line in f:
                identifier, hostname = line.strip().split(',')
                if dest_ip := tracer.resolve_hostname(hostname):
                    if dest_ip != tracer.my_ip:
                        tracer.trace_route(dest_ip, hostname, identifier)
    except Exception as e:
        logger.error(f"Error processing IP list file: {e}")
    finally:
        elapsed_time = time.time() - start_time
        logger.info(f"Total execution time: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    main()
