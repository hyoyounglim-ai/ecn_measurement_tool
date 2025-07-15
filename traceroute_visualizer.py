#!/usr/bin/env python3
"""
트레이스루트 결과 시각화 도구
ECN bleaching 분석 및 네트워크 토폴로지 시각화
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
import matplotlib.patches as mpatches
from flask import Flask, render_template, jsonify, request
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

class TracerouteVisualizer:
    """트레이스루트 결과 시각화 웹 애플리케이션"""
    
    def __init__(self, analyzer: TracerouteAnalyzer):
        self.analyzer = analyzer
        self.app = Flask(__name__)
        self.setup_routes()
    
    def setup_routes(self):
        """Flask 라우트 설정"""
        
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/summary')
        def get_summary():
            return jsonify({
                'total_domains': len(self.analyzer.results),
                'total_routers': len(self.analyzer.router_stats),
                'total_common_paths': len(self.analyzer.common_paths),
                'top_bleaching_routers': [
                    asdict(router) for router in self.analyzer.get_top_bleaching_routers(5)
                ],
                'most_common_routers': [
                    asdict(router) for router in self.analyzer.get_most_common_routers(5)
                ]
            })
        
        @self.app.route('/api/routers')
        def get_routers():
            return jsonify({
                ip: asdict(router_info) 
                for ip, router_info in self.analyzer.router_stats.items()
            })
        
        @self.app.route('/api/paths')
        def get_paths():
            return jsonify([
                {
                    'path_id': path.path_id,
                    'routers': path.routers,
                    'bleaching_points': path.bleaching_points,
                    'frequency': path.frequency,
                    'representative_domains': path.representative_domains
                }
                for path in self.analyzer.common_paths
            ])
        
        @self.app.route('/api/network-graph')
        def get_network_graph():
            G = self.analyzer.generate_network_graph()
            
            # NetworkX 그래프를 JSON으로 변환
            graph_data = {
                'nodes': [
                    {
                        'id': node,
                        'bleaching_rate': G.nodes[node]['bleaching_rate'],
                        'total_occurrences': G.nodes[node]['total_occurrences'],
                        'hop_count': G.nodes[node]['hop_count']
                    }
                    for node in G.nodes()
                ],
                'edges': [
                    {
                        'source': edge[0],
                        'target': edge[1],
                        'weight': G.edges[edge]['weight']
                    }
                    for edge in G.edges()
                ]
            }
            
            return jsonify(graph_data)
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = True):
        """웹 애플리케이션 실행"""
        logger.info(f"웹 애플리케이션 시작: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

def create_html_templates():
    """HTML 템플릿 생성"""
    templates_dir = "templates"
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # 메인 페이지 템플릿
    index_html = '''<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>트레이스루트 ECN 분석 대시보드</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .router-table {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .bleaching-high {
            color: #dc3545;
            font-weight: bold;
        }
        .bleaching-medium {
            color: #ffc107;
            font-weight: bold;
        }
        .bleaching-low {
            color: #28a745;
            font-weight: bold;
        }
        #network-graph {
            width: 100%;
            height: 600px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 트레이스루트 ECN 분석 대시보드</h1>
            <p>네트워크 경로에서의 ECN Bleaching 패턴 분석</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-domains">-</div>
                <div>분석된 도메인</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="total-routers">-</div>
                <div>발견된 라우터</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="common-paths">-</div>
                <div>공통 경로</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="bleaching-incidents">-</div>
                <div>ECN Bleaching 발생</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>📊 ECN Bleaching 발생률 분포</h3>
            <canvas id="bleachingChart" width="400" height="200"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>🔄 라우터 사용 빈도</h3>
            <canvas id="routerChart" width="400" height="200"></canvas>
        </div>
        
        <div class="router-table">
            <h3>🔍 상위 ECN Bleaching 라우터</h3>
            <table id="bleaching-table">
                <thead>
                    <tr>
                        <th>IP 주소</th>
                        <th>Bleaching 횟수</th>
                        <th>총 발생 횟수</th>
                        <th>Bleaching 비율</th>
                        <th>평균 홉 수</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        
        <div class="chart-container">
            <h3>🌍 네트워크 토폴로지</h3>
            <div id="network-graph"></div>
        </div>
    </div>

    <script>
        // 데이터 로드
        async function loadData() {
            try {
                const summary = await fetch('/api/summary').then(r => r.json());
                const routers = await fetch('/api/routers').then(r => r.json());
                const paths = await fetch('/api/paths').then(r => r.json());
                const networkGraph = await fetch('/api/network-graph').then(r => r.json());
                
                updateDashboard(summary, routers, paths, networkGraph);
            } catch (error) {
                console.error('데이터 로드 실패:', error);
            }
        }
        
        function updateDashboard(summary, routers, paths, networkGraph) {
            // 통계 업데이트
            document.getElementById('total-domains').textContent = summary.total_domains;
            document.getElementById('total-routers').textContent = summary.total_routers;
            document.getElementById('common-paths').textContent = summary.total_common_paths;
            
            const totalBleaching = summary.top_bleaching_routers.reduce((sum, r) => sum + r.bleaching_count, 0);
            document.getElementById('bleaching-incidents').textContent = totalBleaching;
            
            // ECN Bleaching 차트
            createBleachingChart(summary.top_bleaching_routers);
            
            // 라우터 사용 빈도 차트
            createRouterChart(summary.most_common_routers);
            
            // 라우터 테이블 업데이트
            updateBleachingTable(summary.top_bleaching_routers);
            
            // 네트워크 그래프 생성
            createNetworkGraph(networkGraph);
        }
        
        function createBleachingChart(routers) {
            const ctx = document.getElementById('bleachingChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: routers.map(r => r.ip.substring(0, 15) + '...'),
                    datasets: [{
                        label: 'ECN Bleaching 횟수',
                        data: routers.map(r => r.bleaching_count),
                        backgroundColor: 'rgba(220, 53, 69, 0.8)',
                        borderColor: 'rgba(220, 53, 69, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        function createRouterChart(routers) {
            const ctx = document.getElementById('routerChart').getContext('2d');
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: routers.map(r => r.ip.substring(0, 15) + '...'),
                    datasets: [{
                        data: routers.map(r => r.total_occurrences),
                        backgroundColor: [
                            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
                            '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
        
        function updateBleachingTable(routers) {
            const tbody = document.querySelector('#bleaching-table tbody');
            tbody.innerHTML = '';
            
            routers.forEach(router => {
                const row = tbody.insertRow();
                row.innerHTML = `
                    <td>${router.ip}</td>
                    <td class="bleaching-high">${router.bleaching_count}</td>
                    <td>${router.total_occurrences}</td>
                    <td class="bleaching-${router.bleaching_rate > 0.5 ? 'high' : router.bleaching_rate > 0.2 ? 'medium' : 'low'}">
                        ${(router.bleaching_rate * 100).toFixed(1)}%
                    </td>
                    <td>${router.hop_count.toFixed(1)}</td>
                `;
            });
        }
        
        function createNetworkGraph(graphData) {
            const width = document.getElementById('network-graph').offsetWidth;
            const height = 600;
            
            const svg = d3.select('#network-graph')
                .append('svg')
                .attr('width', width)
                .attr('height', height);
            
            const simulation = d3.forceSimulation(graphData.nodes)
                .force('link', d3.forceLink(graphData.edges).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2));
            
            const link = svg.append('g')
                .selectAll('line')
                .data(graphData.edges)
                .enter().append('line')
                .attr('stroke', '#999')
                .attr('stroke-opacity', 0.6)
                .attr('stroke-width', d => Math.sqrt(d.weight) * 2);
            
            const node = svg.append('g')
                .selectAll('circle')
                .data(graphData.nodes)
                .enter().append('circle')
                .attr('r', d => Math.sqrt(d.total_occurrences) * 2 + 3)
                .attr('fill', d => d.bleaching_rate > 0.5 ? '#dc3545' : 
                                  d.bleaching_rate > 0.2 ? '#ffc107' : '#28a745')
                .attr('stroke', '#fff')
                .attr('stroke-width', 2)
                .call(d3.drag()
                    .on('start', dragstarted)
                    .on('drag', dragged)
                    .on('end', dragended));
            
            node.append('title')
                .text(d => `${d.id}\\nBleaching: ${d.bleaching_count}\\nOccurrences: ${d.total_occurrences}`);
            
            simulation.on('tick', () => {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                
                node
                    .attr('cx', d => d.x)
                    .attr('cy', d => d.y);
            });
            
            function dragstarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }
            
            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }
            
            function dragended(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }
        }
        
        // 페이지 로드 시 데이터 로드
        document.addEventListener('DOMContentLoaded', loadData);
    </script>
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    logger.info("HTML 템플릿 생성 완료")

def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='트레이스루트 결과 시각화 도구')
    parser.add_argument('--results-dir', default='traceroute', help='결과 디렉토리 (기본값: traceroute)')
    parser.add_argument('--host', default='0.0.0.0', help='웹 서버 호스트 (기본값: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='웹 서버 포트 (기본값: 5000)')
    parser.add_argument('--export', help='분석 결과를 JSON으로 내보낼 파일 경로')
    
    args = parser.parse_args()
    
    # 분석기 생성 및 실행
    analyzer = TracerouteAnalyzer(args.results_dir)
    
    # 결과 로드
    results = analyzer.load_results()
    if not results:
        logger.error("분석할 결과가 없습니다.")
        return
    
    # 분석 실행
    logger.info("트레이스루트 결과 분석 시작")
    analyzer.analyze_routers()
    analyzer.find_common_paths()
    
    # 결과 내보내기 (옵션)
    if args.export:
        analyzer.export_analysis_results(args.export)
    
    # HTML 템플릿 생성
    create_html_templates()
    
    # 웹 애플리케이션 시작
    visualizer = TracerouteVisualizer(analyzer)
    visualizer.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main() 