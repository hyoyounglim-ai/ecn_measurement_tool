#!/usr/bin/env python3
"""
AS 번호 분석 도구
IP 주소에서 AS 정보를 수집하고 분석하여 네트워크 대표성을 평가합니다.
"""

import json
import argparse
import logging
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Set
import requests
import time
from datetime import datetime

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ASInfo:
    as_number: str
    as_name: str
    country: str
    router_count: int
    bleaching_count: int
    bleaching_rate: float

class ASAnalyzer:
    def __init__(self, analysis_file: str = "analysis_results_v2.json"):
        self.analysis_file = analysis_file
        self.analysis_data = {}
        self.as_info = {}
        self.ip_to_as = {}
        self.load_analysis_data()
    
    def load_analysis_data(self):
        with open(self.analysis_file, 'r', encoding='utf-8') as f:
            self.analysis_data = json.load(f)
        logger.info(f"분석 데이터 로드 완료: {self.analysis_file}")
    
    def get_as_info_from_ip(self, ip: str) -> Dict:
        if ip in self.ip_to_as:
            return self.ip_to_as[ip]
        
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                as_info = {
                    'as': data.get('org', '').split()[0] if data.get('org') else 'Unknown',
                    'as_name': data.get('org', 'Unknown'),
                    'country': data.get('country', 'Unknown')
                }
                self.ip_to_as[ip] = as_info
                return as_info
            else:
                return {'as': 'Unknown', 'as_name': 'Unknown', 'country': 'Unknown'}
        except Exception as e:
            logger.warning(f"IP {ip} AS 정보 조회 중 오류: {e}")
            return {'as': 'Unknown', 'as_name': 'Unknown', 'country': 'Unknown'}
    
    def analyze_as_distribution(self):
        logger.info("AS 분포 분석 시작")
        
        router_stats = self.analysis_data.get('router_statistics', {})
        as_data = defaultdict(lambda: {'routers': 0, 'bleaching_count': 0})
        
        for ip, router_data in router_stats.items():
            as_info = self.get_as_info_from_ip(ip)
            as_number = as_info.get('as', 'Unknown')
            
            as_data[as_number]['routers'] += 1
            as_data[as_number]['bleaching_count'] += router_data.get('bleaching_count', 0)
            
            time.sleep(0.1)  # API 호출 제한
        
        for as_number, data in as_data.items():
            bleaching_rate = data['bleaching_count'] / data['routers'] if data['routers'] > 0 else 0
            
            # AS 이름과 국가 정보
            first_ip = next((ip for ip, rd in router_stats.items() 
                           if self.get_as_info_from_ip(ip).get('as') == as_number), None)
            if first_ip:
                first_as_info = self.get_as_info_from_ip(first_ip)
                as_name = first_as_info.get('as_name', 'Unknown')
                country = first_as_info.get('country', 'Unknown')
            else:
                as_name = 'Unknown'
                country = 'Unknown'
            
            self.as_info[as_number] = ASInfo(
                as_number=as_number,
                as_name=as_name,
                country=country,
                router_count=data['routers'],
                bleaching_count=data['bleaching_count'],
                bleaching_rate=bleaching_rate
            )
        
        logger.info(f"총 {len(self.as_info)}개의 AS 분석 완료")
        return self.as_info
    
    def get_top_as_by_router_count(self, top_n: int = 20):
        return sorted(self.as_info.values(), key=lambda x: x.router_count, reverse=True)[:top_n]
    
    def get_top_as_by_bleaching_rate(self, top_n: int = 20):
        return sorted(self.as_info.values(), key=lambda x: x.bleaching_rate, reverse=True)[:top_n]
    
    def calculate_network_representativeness(self):
        total_as = len(self.as_info)
        total_routers = sum(as_info.router_count for as_info in self.as_info.values())
        total_bleaching = sum(as_info.bleaching_count for as_info in self.as_info.values())
        
        top_10_as = self.get_top_as_by_router_count(10)
        top_as_router_count = sum(as_info.router_count for as_info in top_10_as)
        
        return {
            'total_as': total_as,
            'total_routers': total_routers,
            'total_bleaching': total_bleaching,
            'overall_bleaching_rate': total_bleaching / total_routers if total_routers > 0 else 0,
            'top_10_as_router_share': top_as_router_count / total_routers if total_routers > 0 else 0,
            'estimated_global_representativeness': min(total_as / 100000 * 100, 100)
        }
    
    def export_results(self, output_file: str = "as_analysis_results.json"):
        def convert_sets_to_lists(obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, dict):
                return {k: convert_sets_to_lists(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_sets_to_lists(item) for item in obj]
            else:
                return obj
        
        analysis_results = {
            'summary': {
                'total_as': len(self.as_info),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'as_statistics': [convert_sets_to_lists(asdict(as_info)) for as_info in self.as_info.values()],
            'top_as_by_router_count': [convert_sets_to_lists(asdict(as_info)) for as_info in self.get_top_as_by_router_count(20)],
            'top_as_by_bleaching_rate': [convert_sets_to_lists(asdict(as_info)) for as_info in self.get_top_as_by_bleaching_rate(20)],
            'network_representativeness': self.calculate_network_representativeness()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"AS 분석 결과 저장: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='AS 번호 분석 도구')
    parser.add_argument('--analysis-file', default='analysis_results_v2.json', 
                       help='분석 결과 파일 경로')
    parser.add_argument('--export', help='결과 파일 경로')
    
    args = parser.parse_args()
    
    analyzer = ASAnalyzer(args.analysis_file)
    analyzer.analyze_as_distribution()
    
    representativeness = analyzer.calculate_network_representativeness()
    
    logger.info("=" * 60)
    logger.info("AS 분석 결과 요약")
    logger.info("=" * 60)
    logger.info(f"총 AS 수: {representativeness['total_as']}")
    logger.info(f"총 라우터 수: {representativeness['total_routers']}")
    logger.info(f"총 Bleaching 사건: {representativeness['total_bleaching']}")
    logger.info(f"전체 Bleaching 비율: {representativeness['overall_bleaching_rate']:.4f}")
    logger.info(f"상위 10개 AS 라우터 점유율: {representativeness['top_10_as_router_share']:.2%}")
    logger.info(f"추정 전세계 대표성: {representativeness['estimated_global_representativeness']:.1f}%")
    
    top_as = analyzer.get_top_as_by_router_count(5)
    logger.info("\n상위 5개 AS (라우터 수 기준):")
    for i, as_info in enumerate(top_as, 1):
        logger.info(f"{i}. {as_info.as_number} ({as_info.as_name}) - {as_info.router_count}개 라우터")
    
    if args.export:
        analyzer.export_results(args.export)
    else:
        analyzer.export_results()
    
    logger.info("AS 분석 완료!")

if __name__ == "__main__":
    main() 