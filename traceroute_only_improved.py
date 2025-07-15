#!/usr/bin/env python3
import socket
import struct
import tcppacket as rs
import random 
import time
import os
import sys
import argparse
from requests import get
from os import path
from scapy.all import *
import random
import logging
from datetime import date, datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import json
from ipwhois import IPWhois
from pprint import pprint
import numpy as np
import yaml
import bios
from tqdm import tqdm
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
import threading

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('traceroute.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TracerouteHop:
    """트레이스루트 홉 정보를 저장하는 데이터 클래스"""
    hop_number: int
    ip_address: str
    ttl: int
    sent_tos: int
    icmp_tos: int
    icmp_ecn_bit: int
    iperror_tos: int
    iperror_ecn_bit: int
    response_time: float
    status: str  # 'success', 'timeout', 'error'

@dataclass
class TracerouteResult:
    """트레이스루트 결과를 저장하는 데이터 클래스"""
    target_domain: str
    target_ip: str
    source_ip: str
    timestamp: str
    total_hops: int
    successful_hops: int
    bleaching_count: int
    hops: List[TracerouteHop]
    execution_time: float
    metadata: Dict

class TracerouteWorker:
    """멀티스레드 트레이스루트 작업자 클래스"""
    
    def __init__(self, max_workers: int = 5, timeout: float = 0.3, max_hops: int = 30):
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_hops = max_hops
        self.results_lock = Lock()
        self.results = []
        self.my_ip = self._get_my_ip()
        
    def _get_my_ip(self) -> str:
        """내 IP 주소를 가져오는 함수"""
        try:
            logger.info("내 IP 주소를 확인하는 중...")
            my_ip = get('https://api.ipify.org').text
            logger.info(f"내 IP 주소: {my_ip}")
            return my_ip
        except Exception as e:
            logger.error(f"IP 주소 확인 실패: {e}")
            return "unknown"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """IP 주소가 유효한지 검증하는 함수"""
        try:
            if not ip or ip.strip() == "" or ip.upper() in ["N/A", "NULL", "NONE", "UNDEFINED"]:
                return False
            
            # IP 주소 형식 검증
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not part.isdigit():
                    return False
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            return True
        except:
            return False
    
    def perform_traceroute(self, domain_info: Tuple[int, str, str, str]) -> Optional[TracerouteResult]:
        """단일 도메인에 대한 트레이스루트 수행"""
        index, domain_id, domain, ip_addr = domain_info
        
        logger.info(f"[{index+1}] 트레이스루트 시작: {domain} -> {ip_addr} (ID: {domain_id})")
        start_time = time.time()
        
        # IP 주소 검증
        if not self._is_valid_ip(ip_addr):
            logger.warning(f"유효하지 않은 IP 주소 건너뛰기: {ip_addr}")
            return None
        
        if ip_addr == self.my_ip:
            logger.warning(f"자신의 IP와 동일한 대상: {ip_addr}")
            return None
        
        # 트레이스루트 수행
        hops = []
        bleaching_count = 0
        successful_hops = 0
        
        # ICMP 필터 설정
        icmp_filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12))"
        
        logger.debug(f"트레이스루트 시작: {ip_addr} (최대 {self.max_hops} 홉)")
        
        for hop_num in range(1, self.max_hops + 1):
            hop_start_time = time.time()
            
            try:
                # UDP 패킷으로 트레이스루트 수행
                res, unans = sr(
                    IP(dst=ip_addr, ttl=hop_num, tos=1)/UDP(sport=53001, dport=80),
                    timeout=self.timeout,
                    filter=icmp_filter,
                    verbose=0
                )
                
                response_time = time.time() - hop_start_time
                
                if len(res) > 0:
                    successful_hops += 1
                    
                    # 응답 패킷 분석
                    sent_tos = res[0].query[IP].tos
                    icmp_tos = res[0].answer[IP].tos
                    icmp_src = res[0].answer[IP].src
                    icmp_ttl = res[0].answer[IP].ttl
                    iperror_tos = res[0].answer[IPerror].tos
                    icmp_ecn_bit = icmp_tos & 0x3
                    iperror_ecn_bit = iperror_tos & 0x3
                    
                    # ECN bleaching 검사
                    if iperror_ecn_bit != 1:  # tos=1로 설정했으므로
                        bleaching_count += 1
                        logger.debug(f"ECN bleaching 발견: {icmp_src} (홉 {hop_num})")
                    
                    hop = TracerouteHop(
                        hop_number=hop_num,
                        ip_address=icmp_src,
                        ttl=icmp_ttl,
                        sent_tos=sent_tos,
                        icmp_tos=icmp_tos,
                        icmp_ecn_bit=icmp_ecn_bit,
                        iperror_tos=iperror_tos,
                        iperror_ecn_bit=iperror_ecn_bit,
                        response_time=response_time,
                        status='success'
                    )
                    hops.append(hop)
                    
                    # 목적지에 도달했는지 확인
                    if icmp_src == ip_addr:
                        logger.debug(f"목적지 도달: {ip_addr} (홉 {hop_num})")
                        break
                        
                else:
                    # 응답 없음
                    hop = TracerouteHop(
                        hop_number=hop_num,
                        ip_address="*",
                        ttl=hop_num,
                        sent_tos=1,
                        icmp_tos=0,
                        icmp_ecn_bit=0,
                        iperror_tos=0,
                        iperror_ecn_bit=0,
                        response_time=response_time,
                        status='timeout'
                    )
                    hops.append(hop)
                    
            except Exception as e:
                logger.error(f"홉 {hop_num} 처리 중 오류: {e}")
                hop = TracerouteHop(
                    hop_number=hop_num,
                    ip_address="*",
                    ttl=hop_num,
                    sent_tos=1,
                    icmp_tos=0,
                    icmp_ecn_bit=0,
                    iperror_tos=0,
                    iperror_ecn_bit=0,
                    response_time=time.time() - hop_start_time,
                    status='error'
                )
                hops.append(hop)
        
        execution_time = time.time() - start_time
        
        # 결과 생성
        result = TracerouteResult(
            target_domain=domain,
            target_ip=ip_addr,
            source_ip=self.my_ip,
            timestamp=datetime.now().isoformat(),
            total_hops=len(hops),
            successful_hops=successful_hops,
            bleaching_count=bleaching_count,
            hops=hops,
            execution_time=execution_time,
            metadata={
                'domain_id': domain_id,
                'worker_thread': threading.current_thread().name,
                'timeout': self.timeout,
                'max_hops': self.max_hops
            }
        )
        
        logger.info(f"[{index+1}] 트레이스루트 완료: {domain} -> {ip_addr} "
                   f"(성공: {successful_hops}/{len(hops)} 홉, "
                   f"ECN bleaching: {bleaching_count}, "
                   f"소요시간: {execution_time:.2f}초)")
        
        return result
    
    def save_results(self, results: List[TracerouteResult], output_dir: str = "traceroute"):
        """결과를 체계적으로 저장"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 개별 결과 파일들
        for result in results:
            filename = f"traceroute_{result.target_domain}_{result.target_ip}_{timestamp}.json"
            filepath = os.path.join(output_dir, filename)
            
            # dataclass를 dict로 변환
            result_dict = asdict(result)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"결과 저장: {filepath}")
        
        # 통합 요약 파일
        summary = {
            'summary': {
                'total_targets': len(results),
                'successful_traceroutes': len([r for r in results if r.successful_hops > 0]),
                'total_bleaching_incidents': sum(r.bleaching_count for r in results),
                'average_execution_time': sum(r.execution_time for r in results) / len(results) if results else 0,
                'timestamp': timestamp,
                'source_ip': self.my_ip
            },
            'targets': [
                {
                    'domain': r.target_domain,
                    'ip': r.target_ip,
                    'successful_hops': r.successful_hops,
                    'total_hops': r.total_hops,
                    'bleaching_count': r.bleaching_count,
                    'execution_time': r.execution_time
                }
                for r in results
            ]
        }
        
        summary_filename = f"traceroute_summary_{timestamp}.json"
        summary_filepath = os.path.join(output_dir, summary_filename)
        
        with open(summary_filepath, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        logger.info(f"요약 파일 저장: {summary_filepath}")
        
        # 통계 출력
        self._print_statistics(results)
    
    def _print_statistics(self, results: List[TracerouteResult]):
        """통계 정보 출력"""
        if not results:
            logger.warning("출력할 결과가 없습니다.")
            return
        
        successful_count = len([r for r in results if r.successful_hops > 0])
        total_bleaching = sum(r.bleaching_count for r in results)
        avg_time = sum(r.execution_time for r in results) / len(results)
        
        logger.info("=" * 60)
        logger.info("트레이스루트 결과 통계")
        logger.info("=" * 60)
        logger.info(f"총 대상: {len(results)}개")
        logger.info(f"성공한 트레이스루트: {successful_count}개 ({successful_count/len(results)*100:.1f}%)")
        logger.info(f"총 ECN bleaching 발생: {total_bleaching}회")
        logger.info(f"평균 실행 시간: {avg_time:.2f}초")
        logger.info("=" * 60)
    
    def run_traceroutes(self, ip_list_file: str) -> List[TracerouteResult]:
        """메인 실행 함수 - 멀티스레드로 트레이스루트 수행"""
        logger.info("트레이스루트 작업 시작")
        
        # IP 리스트 읽기
        try:
            with open(ip_list_file, "r") as f:
                ip_list = [line.strip().split(',') for line in f if line.strip()]
            logger.info(f"총 {len(ip_list)}개의 대상 로드 완료")
        except Exception as e:
            logger.error(f"IP 리스트 파일 읽기 실패: {e}")
            return []
        
        # 도메인 정보 준비 (Number, Domain, IP_Address 형식)
        domain_infos = []
        for i, item in enumerate(ip_list):
            if len(item) >= 3:  # 최소 3개 컬럼이 있는지 확인
                domain_infos.append((i, item[0], item[1], item[2]))  # index, number, domain, ip
            else:
                logger.warning(f"잘못된 형식의 라인 건너뛰기: {item}")
        
        logger.info(f"유효한 대상 {len(domain_infos)}개 준비 완료")
        
        results = []
        
        # ThreadPoolExecutor를 사용한 멀티스레드 실행
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 작업 제출
            future_to_domain = {
                executor.submit(self.perform_traceroute, domain_info): domain_info 
                for domain_info in domain_infos
            }
            
            # 진행률 표시와 함께 결과 수집
            with tqdm(total=len(domain_infos), desc="트레이스루트 진행률") as pbar:
                for future in as_completed(future_to_domain):
                    domain_info = future_to_domain[future]
                    index, domain_id, domain, ip_addr = domain_info
                    
                    try:
                        result = future.result()
                        if result:
                            with self.results_lock:
                                results.append(result)
                        pbar.update(1)
                        pbar.set_postfix({
                            '현재': f"{domain[:15]}...",
                            'IP': ip_addr,
                            '완료': f"{len(results)}/{len(domain_infos)}"
                        })
                        
                    except Exception as e:
                        logger.error(f"도메인 {domain} ({ip_addr}) 처리 중 예외 발생: {e}")
                        pbar.update(1)
        
        logger.info(f"모든 트레이스루트 완료. 총 {len(results)}개 결과 수집")
        return results

def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='멀티스레드 트레이스루트 도구')
    parser.add_argument('ip_list', help='IP 리스트 파일 경로')
    parser.add_argument('--workers', type=int, default=5, help='동시 실행할 워커 수 (기본값: 5)')
    parser.add_argument('--timeout', type=float, default=0.3, help='패킷 타임아웃 (기본값: 0.3초)')
    parser.add_argument('--max-hops', type=int, default=30, help='최대 홉 수 (기본값: 30)')
    parser.add_argument('--output-dir', default='traceroute', help='출력 디렉토리 (기본값: traceroute)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.ip_list):
        logger.error(f"IP 리스트 파일을 찾을 수 없습니다: {args.ip_list}")
        return
    
    start_time = time.time()
    
    # 트레이스루트 워커 생성 및 실행
    worker = TracerouteWorker(
        max_workers=args.workers,
        timeout=args.timeout,
        max_hops=args.max_hops
    )
    
    try:
        results = worker.run_traceroutes(args.ip_list)
        worker.save_results(results, args.output_dir)
        
        total_time = time.time() - start_time
        logger.info(f"전체 실행 시간: {total_time:.2f}초")
        
    except KeyboardInterrupt:
        logger.info("사용자에 의해 중단되었습니다.")
    except Exception as e:
        logger.error(f"실행 중 오류 발생: {e}")

if __name__ == "__main__":
    main() 