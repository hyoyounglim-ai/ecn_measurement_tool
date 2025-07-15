#!/usr/bin/env python3
"""
트레이스루트 결과 분석 도구 v2
1단계: 데이터 로더 및 기본 분석기
"""

import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, Counter
import pandas as pd
import numpy as np
from dataclasses import dataclass, asdict
import logging
import glob

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('traceroute_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RouterAnalysis:
    """라우터 분석 결과를 저장하는 데이터 클래스"""
    ip: str
    total_occurrences: int
    bleaching_count: int
    bleaching_rate: float
    avg_hop_position: float
    domains_reached: Set[str]
    avg_response_time: float
    success_rate: float

@dataclass
class PathAnalysis:
    """경로 분석 결과를 저장하는 데이터 클래스"""
    path_id: str
    routers: List[str]
    bleaching_points: List[str]
    frequency: int
    representative_domains: List[str]
    avg_hops: float
    avg_bleaching_count: float

@dataclass
class DomainAnalysis:
    """도메인 분석 결과를 저장하는 데이터 클래스"""
    domain: str
    ip: str
    successful_hops: int
    total_hops: int
    bleaching_count: int
    execution_time: float
    success_rate: float
    bleaching_rate: float
    avg_response_time: float

class TracerouteDataLoader:
    """트레이스루트 결과 데이터 로더"""
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.results = []
        self.summary = None
        
    def load_all_data(self) -> Tuple[List[Dict], Dict]:
        """모든 JSON 파일을 로드"""
        logger.info(f"데이터 디렉토리에서 파일들을 로드 중: {self.data_dir}")
        
        if not os.path.exists(self.data_dir):
            logger.error(f"데이터 디렉토리가 존재하지 않습니다: {self.data_dir}")
            return [], {}
        
        # 개별 결과 파일들 로드
        individual_files = glob.glob(os.path.join(self.data_dir, "traceroute_*.json"))
        individual_files = [f for f in individual_files if "summary" not in f]
        
        logger.info(f"개별 결과 파일 {len(individual_files)}개 발견")
        
        for filepath in individual_files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    result = json.load(f)
                    self.results.append(result)
                    logger.debug(f"로드됨: {os.path.basename(filepath)}")
            except Exception as e:
                logger.error(f"파일 로드 실패 {filepath}: {e}")
        
        # 요약 파일 로드
        summary_files = glob.glob(os.path.join(self.data_dir, "*summary*.json"))
        if summary_files:
            try:
                with open(summary_files[0], 'r', encoding='utf-8') as f:
                    self.summary = json.load(f)
                    logger.info(f"요약 파일 로드됨: {os.path.basename(summary_files[0])}")
            except Exception as e:
                logger.error(f"요약 파일 로드 실패: {e}")
        
        logger.info(f"총 {len(self.results)}개의 결과 파일 로드 완료")
        return self.results, self.summary
    
    def get_basic_statistics(self) -> Dict:
        """기본 통계 정보 계산"""
        if not self.results:
            return {}
        
        total_domains = len(self.results)
        successful_traceroutes = len([r for r in self.results if r.get('successful_hops', 0) > 0])
        total_bleaching = sum(r.get('bleaching_count', 0) for r in self.results)
        avg_execution_time = np.mean([r.get('execution_time', 0) for r in self.results])
        
        # 라우터 통계
        all_routers = set()
        bleaching_routers = set()
        
        for result in self.results:
            for hop in result.get('hops', []):
                if hop.get('ip_address') and hop['ip_address'] != '*':
                    all_routers.add(hop['ip_address'])
                    if hop.get('iperror_ecn_bit', 1) != 1:  # ECN bleaching 발생
                        bleaching_routers.add(hop['ip_address'])
        
        stats = {
            'total_domains': total_domains,
            'successful_traceroutes': successful_traceroutes,
            'success_rate': successful_traceroutes / total_domains if total_domains > 0 else 0,
            'total_bleaching_incidents': total_bleaching,
            'average_execution_time': avg_execution_time,
            'total_unique_routers': len(all_routers),
            'routers_with_bleaching': len(bleaching_routers),
            'bleaching_router_rate': len(bleaching_routers) / len(all_routers) if all_routers else 0
        }
        
        return stats

class TracerouteAnalyzer:
    """트레이스루트 결과 분석기"""
    
    def __init__(self, data_loader: TracerouteDataLoader):
        self.data_loader = data_loader
        self.results = data_loader.results
        self.router_analysis = {}
        self.path_analysis = []
        self.domain_analysis = []
        
    def analyze_routers(self) -> Dict[str, RouterAnalysis]:
        """라우터별 상세 분석"""
        logger.info("라우터 분석 시작")
        
        router_data = defaultdict(lambda: {
            'occurrences': [],
            'bleaching_events': [],
            'domains': set(),
            'response_times': [],
            'success_count': 0,
            'total_count': 0
        })
        
        # 모든 결과에서 라우터 정보 수집
        for result in self.results:
            domain = result.get('target_domain', 'unknown')
            for hop in result.get('hops', []):
                if hop.get('ip_address') and hop['ip_address'] != '*':
                    ip = hop['ip_address']
                    router_data[ip]['occurrences'].append(hop.get('hop_number', 0))
                    router_data[ip]['domains'].add(domain)
                    router_data[ip]['total_count'] += 1
                    
                    if hop.get('response_time'):
                        router_data[ip]['response_times'].append(hop['response_time'])
                    
                    if hop.get('status') == 'success':
                        router_data[ip]['success_count'] += 1
                    
                    # ECN bleaching 검사
                    if hop.get('iperror_ecn_bit', 1) != 1:
                        router_data[ip]['bleaching_events'].append({
                            'domain': domain,
                            'hop': hop.get('hop_number', 0),
                            'original_tos': 1,
                            'received_tos': hop.get('iperror_ecn_bit', 0)
                        })
        
        # RouterAnalysis 객체로 변환
        for ip, data in router_data.items():
            bleaching_count = len(data['bleaching_events'])
            total_occurrences = data['total_count']
            bleaching_rate = bleaching_count / total_occurrences if total_occurrences > 0 else 0
            success_rate = data['success_count'] / total_occurrences if total_occurrences > 0 else 0
            
            self.router_analysis[ip] = RouterAnalysis(
                ip=ip,
                total_occurrences=total_occurrences,
                bleaching_count=bleaching_count,
                bleaching_rate=bleaching_rate,
                avg_hop_position=np.mean(data['occurrences']) if data['occurrences'] else 0,
                domains_reached=data['domains'],
                avg_response_time=np.mean(data['response_times']) if data['response_times'] else 0,
                success_rate=success_rate
            )
        
        logger.info(f"총 {len(self.router_analysis)}개의 라우터 분석 완료")
        return self.router_analysis
    
    def analyze_domains(self) -> List[DomainAnalysis]:
        """도메인별 상세 분석"""
        logger.info("도메인 분석 시작")
        
        for result in self.results:
            domain = result.get('target_domain', 'unknown')
            ip = result.get('target_ip', 'unknown')
            successful_hops = result.get('successful_hops', 0)
            total_hops = result.get('total_hops', 0)
            bleaching_count = result.get('bleaching_count', 0)
            execution_time = result.get('execution_time', 0)
            
            # 응답 시간 계산
            response_times = []
            for hop in result.get('hops', []):
                if hop.get('response_time'):
                    response_times.append(hop['response_time'])
            
            avg_response_time = np.mean(response_times) if response_times else 0
            success_rate = successful_hops / total_hops if total_hops > 0 else 0
            bleaching_rate = bleaching_count / total_hops if total_hops > 0 else 0
            
            domain_analysis = DomainAnalysis(
                domain=domain,
                ip=ip,
                successful_hops=successful_hops,
                total_hops=total_hops,
                bleaching_count=bleaching_count,
                execution_time=execution_time,
                success_rate=success_rate,
                bleaching_rate=bleaching_rate,
                avg_response_time=avg_response_time
            )
            
            self.domain_analysis.append(domain_analysis)
        
        logger.info(f"총 {len(self.domain_analysis)}개의 도메인 분석 완료")
        return self.domain_analysis
    
    def find_common_paths(self) -> List[PathAnalysis]:
        """공통 경로 찾기"""
        logger.info("공통 경로 분석 시작")
        
        # 모든 경로를 수집
        all_paths = []
        for result in self.results:
            path = []
            for hop in result.get('hops', []):
                if hop.get('status') == 'success' and hop.get('ip_address') and hop['ip_address'] != '*':
                    path.append(hop['ip_address'])
            if path:
                all_paths.append((tuple(path), result.get('target_domain', 'unknown')))
        
        # 경로별 빈도 계산
        path_counter = Counter(path for path, _ in all_paths)
        
        # 공통 경로 분석
        for path, frequency in path_counter.most_common():
            if frequency >= 2:  # 2개 이상의 도메인에서 공통으로 나타나는 경로
                # 해당 경로를 사용하는 도메인들 찾기
                domains = [domain for p, domain in all_paths if p == path]
                
                # bleaching 포인트 찾기
                bleaching_points = []
                for result in self.results:
                    if result.get('target_domain') in domains:
                        for hop in result.get('hops', []):
                            if (hop.get('status') == 'success' and 
                                hop.get('ip_address') in path and
                                hop.get('iperror_ecn_bit', 1) != 1):
                                bleaching_points.append(hop['ip_address'])
                
                # 평균 홉 수와 bleaching 수 계산
                avg_hops = np.mean([len(p) for p, _ in all_paths if p == path])
                avg_bleaching = np.mean([
                    sum(1 for hop in result.get('hops', []) 
                        if hop.get('iperror_ecn_bit', 1) != 1)
                    for result in self.results 
                    if result.get('target_domain') in domains
                ])
                
                path_analysis = PathAnalysis(
                    path_id=f"path_{len(self.path_analysis)}",
                    routers=list(path),
                    bleaching_points=list(set(bleaching_points)),
                    frequency=frequency,
                    representative_domains=domains[:5],  # 대표 도메인 5개
                    avg_hops=avg_hops,
                    avg_bleaching_count=avg_bleaching
                )
                self.path_analysis.append(path_analysis)
        
        logger.info(f"총 {len(self.path_analysis)}개의 공통 경로 발견")
        return self.path_analysis
    
    def get_top_bleaching_routers(self, top_n: int = 10) -> List[RouterAnalysis]:
        """ECN bleaching이 가장 많이 발생하는 라우터들"""
        sorted_routers = sorted(
            self.router_analysis.values(),
            key=lambda x: x.bleaching_count,
            reverse=True
        )
        return sorted_routers[:top_n]
    
    def get_most_common_routers(self, top_n: int = 10) -> List[RouterAnalysis]:
        """가장 자주 나타나는 라우터들"""
        sorted_routers = sorted(
            self.router_analysis.values(),
            key=lambda x: x.total_occurrences,
            reverse=True
        )
        return sorted_routers[:top_n]
    
    def export_analysis_results(self, output_file: str = "analysis_results_v2.json"):
        """분석 결과를 JSON으로 내보내기"""
        # Set을 list로 변환하는 헬퍼 함수
        def convert_sets_to_lists(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets_to_lists(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets_to_lists(item) for item in obj]
            else:
                return obj
        
        # 시작지점들 추출
        source_ips = set()
        for result in self.results:
            if result.get('source_ip'):
                source_ips.add(result['source_ip'])
        
        analysis_data = {
            'summary': {
                'total_domains': len(self.results),
                'total_routers': len(self.router_analysis),
                'total_common_paths': len(self.path_analysis),
                'analysis_timestamp': datetime.now().isoformat(),
                'source_ips': list(source_ips) if source_ips else ['127.0.0.1']
            },
            'router_statistics': {
                ip: convert_sets_to_lists(asdict(router_info)) for ip, router_info in self.router_analysis.items()
            },
            'domain_statistics': [
                convert_sets_to_lists(asdict(domain_info)) for domain_info in self.domain_analysis
            ],
            'common_paths': [
                {
                    'path_id': path.path_id,
                    'routers': path.routers,
                    'bleaching_points': path.bleaching_points,
                    'frequency': path.frequency,
                    'representative_domains': path.representative_domains,
                    'avg_hops': path.avg_hops,
                    'avg_bleaching_count': path.avg_bleaching_count
                }
                for path in self.path_analysis
            ],
            'top_bleaching_routers': [
                convert_sets_to_lists(asdict(router)) for router in self.get_top_bleaching_routers(10)
            ],
            'most_common_routers': [
                convert_sets_to_lists(asdict(router)) for router in self.get_most_common_routers(10)
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"분석 결과 저장: {output_file}")

def main():
    """메인 함수 - 1단계 테스트"""
    parser = argparse.ArgumentParser(description='트레이스루트 결과 분석 도구 v2 - 1단계')
    parser.add_argument('--data-dir', default='traceroute_test_1', help='데이터 디렉토리 (기본값: traceroute_test_1)')
    parser.add_argument('--export', help='분석 결과를 JSON으로 내보낼 파일 경로')
    
    args = parser.parse_args()
    
    # 데이터 로더 생성 및 실행
    data_loader = TracerouteDataLoader(args.data_dir)
    results, summary = data_loader.load_all_data()
    
    if not results:
        logger.error("분석할 결과가 없습니다.")
        return
    
    # 기본 통계 출력
    basic_stats = data_loader.get_basic_statistics()
    logger.info("=" * 60)
    logger.info("기본 통계")
    logger.info("=" * 60)
    for key, value in basic_stats.items():
        if isinstance(value, float):
            logger.info(f"{key}: {value:.3f}")
        else:
            logger.info(f"{key}: {value}")
    
    # 분석기 생성 및 실행
    analyzer = TracerouteAnalyzer(data_loader)
    
    logger.info("트레이스루트 결과 분석 시작")
    analyzer.analyze_routers()
    analyzer.analyze_domains()
    analyzer.find_common_paths()
    
    # 결과 내보내기 (옵션)
    if args.export:
        analyzer.export_analysis_results(args.export)
    else:
        analyzer.export_analysis_results()
    
    logger.info("1단계 분석 완료!")

if __name__ == "__main__":
    main() 