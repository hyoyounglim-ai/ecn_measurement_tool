#!/usr/bin/env python3
"""
트레이스루트 결과 웹 시각화 도구
"""

from flask import Flask, render_template, jsonify
import os
import json
from traceroute_analyzer import TracerouteAnalyzer
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TracerouteVisualizer:
    def __init__(self, analyzer: TracerouteAnalyzer):
        self.analyzer = analyzer
        self.app = Flask(__name__)
        self.setup_routes()
    
    def setup_routes(self):
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
                    {
                        'ip': router.ip,
                        'bleaching_count': router.bleaching_count,
                        'total_occurrences': router.total_occurrences,
                        'bleaching_rate': router.bleaching_rate,
                        'hop_count': router.hop_count
                    }
                    for router in self.analyzer.get_top_bleaching_routers(5)
                ],
                'most_common_routers': [
                    {
                        'ip': router.ip,
                        'total_occurrences': router.total_occurrences,
                        'bleaching_count': router.bleaching_count,
                        'bleaching_rate': router.bleaching_rate
                    }
                    for router in self.analyzer.get_most_common_routers(5)
                ]
            })
        
        @self.app.route('/api/routers')
        def get_routers():
            return jsonify({
                ip: {
                    'ip': router_info.ip,
                    'hop_count': router_info.hop_count,
                    'bleaching_count': router_info.bleaching_count,
                    'total_occurrences': router_info.total_occurrences,
                    'bleaching_rate': router_info.bleaching_rate,
                    'domains_reached': list(router_info.domains_reached)
                }
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
    
    def run(self, host='0.0.0.0', port=5000, debug=True):
        logger.info(f"웹 애플리케이션 시작: http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

def create_html_templates():
    templates_dir = "templates"
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
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
        .bleaching-high { color: #dc3545; font-weight: bold; }
        .bleaching-medium { color: #ffc107; font-weight: bold; }
        .bleaching-low { color: #28a745; font-weight: bold; }
        #network-graph {
            width: 100%;
            height: 600px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .path-info {
            background: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
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
            <h3>🛣️ 공통 경로 분석</h3>
            <div id="common-paths"></div>
        </div>
        
        <div class="chart-container">
            <h3>🌍 네트워크 토폴로지</h3>
            <div id="network-graph"></div>
        </div>
    </div>

    <script>
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
            document.getElementById('total-domains').textContent = summary.total_domains;
            document.getElementById('total-routers').textContent = summary.total_routers;
            document.getElementById('common-paths').textContent = summary.total_common_paths;
            
            const totalBleaching = summary.top_bleaching_routers.reduce((sum, r) => sum + r.bleaching_count, 0);
            document.getElementById('bleaching-incidents').textContent = totalBleaching;
            
            createBleachingChart(summary.top_bleaching_routers);
            createRouterChart(summary.most_common_routers);
            updateBleachingTable(summary.top_bleaching_routers);
            displayCommonPaths(paths);
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
                    scales: { y: { beginAtZero: true } }
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
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: 'bottom' } }
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
        
        function displayCommonPaths(paths) {
            const container = document.getElementById('common-paths');
            container.innerHTML = '';
            
            paths.forEach(path => {
                const pathDiv = document.createElement('div');
                pathDiv.className = 'path-info';
                pathDiv.innerHTML = `
                    <h4>경로 ${path.path_id} (빈도: ${path.frequency})</h4>
                    <p><strong>라우터:</strong> ${path.routers.join(' → ')}</p>
                    <p><strong>Bleaching 포인트:</strong> ${path.bleaching_points.length > 0 ? path.bleaching_points.join(', ') : '없음'}</p>
                    <p><strong>대표 도메인:</strong> ${path.representative_domains.join(', ')}</p>
                `;
                container.appendChild(pathDiv);
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
                .text(d => `${d.id}\\nBleaching Rate: ${(d.bleaching_rate * 100).toFixed(1)}%\\nOccurrences: ${d.total_occurrences}`);
            
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
        
        document.addEventListener('DOMContentLoaded', loadData);
    </script>
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    logger.info("HTML 템플릿 생성 완료")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='트레이스루트 결과 시각화 웹 애플리케이션')
    parser.add_argument('--results-dir', default='traceroute', help='결과 디렉토리 (기본값: traceroute)')
    parser.add_argument('--host', default='0.0.0.0', help='웹 서버 호스트 (기본값: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='웹 서버 포트 (기본값: 5000)')
    
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
    
    # HTML 템플릿 생성
    create_html_templates()
    
    # 웹 애플리케이션 시작
    visualizer = TracerouteVisualizer(analyzer)
    visualizer.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main() 