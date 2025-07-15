#!/usr/bin/env python3
"""
트레이스루트 결과 분석 도구
ECN bleaching 분석 및 네트워크 토폴로지 분석
"""

import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict, Counter
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from dataclasses import dataclass, asdict
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class RouterInfo:
    """라우터 정보를 저장하는 데이터 클래스"""
    ip: str
    hop_count: int
    bleaching_count: int
    total_occurrences: int
    bleaching_rate: float
    domains_reached: Set[str]
    asn_info: Optional[str] = None
    location: Optional[str] = None

@dataclass
class PathAnalysis:
    """경로 분석 결과를 저장하는 데이터 클래스"""
    path_id: str
    routers: List[str]
    bleaching_points: List[str]
    common_prefix_length: int
    frequency: int
    representative_domains: List[str]

class TracerouteAnalyzer:
    """트레이스루트 결과 분석 클래스"""
    
    def __init__(self, results_dir: str = "traceroute"):
        self.results_dir = results_dir
        self.results = []
        self.router_stats = {}
        self.path_analysis = {}
        self.common_paths = []
        
    def load_results(self) -> List[Dict]:
        """JSON 결과 파일들을 로드"""
        logger.info(f"결과 디렉토리에서 파일들을 로드 중: {self.results_dir}")
        
        if not os.path.exists(self.results_dir):
            logger.error(f"결과 디렉토리가 존재하지 않습니다: {self.results_dir}")
            return []
        
        results = []
        for filename in os.listdir(self.results_dir):
            if filename.endswith('.json') and filename.startswith('traceroute_'):
                filepath = os.path.join(self.results_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        result = json.load(f)
                        results.append(result)
                        logger.debug(f"로드됨: {filename}")
                except Exception as e:
                    logger.error(f"파일 로드 실패 {filename}: {e}")
        
        self.results = results
        logger.info(f"총 {len(results)}개의 결과 파일 로드 완료")
        return results
    
    def analyze_routers(self) -> Dict[str, RouterInfo]:
        """라우터별 통계 분석"""
        logger.info("라우터 통계 분석 시작")
        
        router_data = defaultdict(lambda: {
            'hop_counts': [],
            'bleaching_events': [],
            'domains': set(),
            'total_occurrences': 0
        })
        
        # 모든 결과에서 라우터 정보 수집
        for result in self.results:
            domain = result['target_domain']
            for hop in result['hops']:
                if hop['status'] == 'success' and hop['ip_address'] != '*':
                    ip = hop['ip_address']
                    router_data[ip]['hop_counts'].append(hop['hop_number'])
                    router_data[ip]['domains'].add(domain)
                    router_data[ip]['total_occurrences'] += 1
                    
                    # ECN bleaching 검사
                    if hop['iperror_ecn_bit'] != 1:  # tos=1로 설정했으므로
                        router_data[ip]['bleaching_events'].append({
                            'domain': domain,
                            'hop': hop['hop_number'],
                            'original_tos': 1,
                            'received_tos': hop['iperror_ecn_bit']
                        })
        
        # RouterInfo 객체로 변환
        router_stats = {}
        for ip, data in router_data.items():
            bleaching_count = len(data['bleaching_events'])
            total_occurrences = data['total_occurrences']
            bleaching_rate = bleaching_count / total_occurrences if total_occurrences > 0 else 0
            
            router_stats[ip] = RouterInfo(
                ip=ip,
                hop_count=np.mean(data['hop_counts']) if data['hop_counts'] else 0,
                bleaching_count=bleaching_count,
                total_occurrences=total_occurrences,
                bleaching_rate=bleaching_rate,
                domains_reached=data['domains']
            )
        
        self.router_stats = router_stats
        logger.info(f"총 {len(router_stats)}개의 고유 라우터 분석 완료")
        return router_stats
    
    def find_common_paths(self) -> List[PathAnalysis]:
        """공통 경로 찾기"""
        logger.info("공통 경로 분석 시작")
        
        # 모든 경로를 수집
        all_paths = []
        for result in self.results:
            path = []
            for hop in result['hops']:
                if hop['status'] == 'success' and hop['ip_address'] != '*':
                    path.append(hop['ip_address'])
            if path:
                all_paths.append((tuple(path), result['target_domain']))
        
        # 경로별 빈도 계산
        path_counter = Counter(path for path, _ in all_paths)
        
        # 공통 경로 분석
        common_paths = []
        for path, frequency in path_counter.most_common():
            if frequency >= 2:  # 2개 이상의 도메인에서 공통으로 나타나는 경로
                # 해당 경로를 사용하는 도메인들 찾기
                domains = [domain for p, domain in all_paths if p == path]
                
                # bleaching 포인트 찾기
                bleaching_points = []
                for result in self.results:
                    if result['target_domain'] in domains:
                        for hop in result['hops']:
                            if (hop['status'] == 'success' and 
                                hop['ip_address'] in path and
                                hop['iperror_ecn_bit'] != 1):
                                bleaching_points.append(hop['ip_address'])
                
                # 공통 prefix 길이 계산
                common_prefix_length = self._find_common_prefix_length(path, all_paths)
                
                path_analysis = PathAnalysis(
                    path_id=f"path_{len(common_paths)}",
                    routers=list(path),
                    bleaching_points=list(set(bleaching_points)),
                    common_prefix_length=common_prefix_length,
                    frequency=frequency,
                    representative_domains=domains[:5]  # 대표 도메인 5개
                )
                common_paths.append(path_analysis)
        
        self.common_paths = common_paths
        logger.info(f"총 {len(common_paths)}개의 공통 경로 발견")
        return common_paths
    
    def _find_common_prefix_length(self, path: Tuple[str, ...], all_paths: List[Tuple[Tuple[str, ...], str]]) -> int:
        """경로의 공통 prefix 길이 계산"""
        max_prefix = 0
        for other_path, _ in all_paths:
            if other_path != path:
                prefix_len = 0
                for i, router in enumerate(path):
                    if i < len(other_path) and other_path[i] == router:
                        prefix_len += 1
                    else:
                        break
                max_prefix = max(max_prefix, prefix_len)
        return max_prefix
    
    def generate_network_graph(self) -> nx.DiGraph:
        """네트워크 그래프 생성"""
        logger.info("네트워크 그래프 생성 시작")
        
        G = nx.DiGraph()
        
        # 노드 추가 (라우터들)
        for ip, router_info in self.router_stats.items():
            G.add_node(ip, 
                      bleaching_rate=router_info.bleaching_rate,
                      total_occurrences=router_info.total_occurrences,
                      hop_count=router_info.hop_count)
        
        # 엣지 추가 (경로들)
        for result in self.results:
            prev_router = None
            for hop in result['hops']:
                if hop['status'] == 'success' and hop['ip_address'] != '*':
                    current_router = hop['ip_address']
                    if prev_router:
                        if G.has_edge(prev_router, current_router):
                            G[prev_router][current_router]['weight'] += 1
                        else:
                            G.add_edge(prev_router, current_router, weight=1)
                    prev_router = current_router
        
        logger.info(f"네트워크 그래프 생성 완료: {G.number_of_nodes()} 노드, {G.number_of_edges()} 엣지")
        return G
    
    def get_top_bleaching_routers(self, top_n: int = 10) -> List[RouterInfo]:
        """ECN bleaching이 가장 많이 발생하는 라우터들"""
        sorted_routers = sorted(
            self.router_stats.values(),
            key=lambda x: x.bleaching_count,
            reverse=True
        )
        return sorted_routers[:top_n]
    
    def get_most_common_routers(self, top_n: int = 10) -> List[RouterInfo]:
        """가장 자주 나타나는 라우터들"""
        sorted_routers = sorted(
            self.router_stats.values(),
            key=lambda x: x.total_occurrences,
            reverse=True
        )
        return sorted_routers[:top_n]
    
    def export_analysis_results(self, output_file: str = "analysis_results.json"):
        """분석 결과를 JSON으로 내보내기"""
        analysis_data = {
            'summary': {
                'total_domains': len(self.results),
                'total_routers': len(self.router_stats),
                'total_common_paths': len(self.common_paths),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'router_statistics': {
                ip: asdict(router_info) for ip, router_info in self.router_stats.items()
            },
            'common_paths': [
                {
                    'path_id': path.path_id,
                    'routers': path.routers,
                    'bleaching_points': path.bleaching_points,
                    'frequency': path.frequency,
                    'representative_domains': path.representative_domains
                }
                for path in self.common_paths
            ],
            'top_bleaching_routers': [
                asdict(router) for router in self.get_top_bleaching_routers(10)
            ],
            'most_common_routers': [
                asdict(router) for router in self.get_most_common_routers(10)
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"분석 결과 저장: {output_file}") 