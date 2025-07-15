#!/usr/bin/env python3
"""
트레이스루트 결과 웹 시각화 도구 v2
2단계: 웹 기반 시각화 인터페이스
"""

import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, render_template, jsonify, request, send_from_directory
import logging
from traceroute_analyzer_v2 import TracerouteDataLoader, TracerouteAnalyzer

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

class WebVisualizer:
    """웹 시각화 클래스"""
    
    def __init__(self, analysis_file: str = "analysis_results_v2.json"):
        self.analysis_file = analysis_file
        self.analysis_data = None
        self.load_analysis_data()
    
    def load_analysis_data(self):
        """분석 결과 데이터 로드"""
        try:
            with open(self.analysis_file, 'r', encoding='utf-8') as f:
                self.analysis_data = json.load(f)
            logger.info(f"분석 데이터 로드 완료: {self.analysis_file}")
        except FileNotFoundError:
            logger.error(f"분석 파일을 찾을 수 없습니다: {self.analysis_file}")
            self.analysis_data = {}
        except Exception as e:
            logger.error(f"분석 데이터 로드 실패: {e}")
            self.analysis_data = {}
    
    def get_summary_data(self) -> Dict:
        """요약 데이터 반환"""
        return self.analysis_data.get('summary', {})
    
    def get_router_statistics(self, limit: int = 50) -> List[Dict]:
        """라우터 통계 데이터 반환"""
        router_stats = self.analysis_data.get('router_statistics', {})
        
        # bleaching rate로 정렬
        sorted_routers = sorted(
            router_stats.items(),
            key=lambda x: x[1].get('bleaching_rate', 0),
            reverse=True
        )
        
        return [
            {
                'ip': ip,
                'total_occurrences': data.get('total_occurrences', 0),
                'bleaching_count': data.get('bleaching_count', 0),
                'bleaching_rate': data.get('bleaching_rate', 0),
                'avg_hop_position': data.get('avg_hop_position', 0),
                'avg_response_time': data.get('avg_response_time', 0),
                'success_rate': data.get('success_rate', 0),
                'domains_reached_count': len(data.get('domains_reached', []))
            }
            for ip, data in sorted_routers[:limit]
        ]
    
    def get_domain_statistics(self, limit: int = 50) -> List[Dict]:
        """도메인 통계 데이터 반환"""
        domain_stats = self.analysis_data.get('domain_statistics', [])
        
        # bleaching rate로 정렬
        sorted_domains = sorted(
            domain_stats,
            key=lambda x: x.get('bleaching_rate', 0),
            reverse=True
        )
        
        return sorted_domains[:limit]
    
    def get_common_paths(self, limit: int = 20) -> List[Dict]:
        """공통 경로 데이터 반환"""
        common_paths = self.analysis_data.get('common_paths', [])
        
        # frequency로 정렬
        sorted_paths = sorted(
            common_paths,
            key=lambda x: x.get('frequency', 0),
            reverse=True
        )
        
        return sorted_paths[:limit]
    
    def get_top_bleaching_routers(self) -> List[Dict]:
        """상위 bleaching 라우터 반환"""
        return self.analysis_data.get('top_bleaching_routers', [])
    
    def get_most_common_routers(self) -> List[Dict]:
        """가장 자주 나타나는 라우터 반환"""
        return self.analysis_data.get('most_common_routers', [])
    
    def get_network_topology_data(self) -> Dict:
        """네트워크 토폴로지 데이터 생성"""
        router_stats = self.analysis_data.get('router_statistics', {})
        common_paths = self.analysis_data.get('common_paths', [])
        summary = self.analysis_data.get('summary', {})
        
        # 시작지점 노드들 추가
        source_ips = summary.get('source_ips', ['127.0.0.1'])
        nodes = []
        for source_ip in source_ips:
            nodes.append({
                'id': source_ip,
                'group': 'source',
                'bleaching_rate': 0,
                'occurrences': 0,
                'avg_hop_position': 0,
                'hop_level': 0
            })
        
        # 라우터 노드들 추가
        for ip, data in router_stats.items():
            nodes.append({
                'id': ip,
                'group': 'router',
                'bleaching_rate': data.get('bleaching_rate', 0),
                'occurrences': data.get('total_occurrences', 0),
                'avg_hop_position': data.get('avg_hop_position', 0),
                'hop_level': round(data.get('avg_hop_position', 0))
            })
        
        # 엣지 데이터 (경로들)
        edges = []
        
        # 시작지점에서 첫 번째 라우터로 연결선 추가
        first_routers = set()
        for path in common_paths:
            routers = path.get('routers', [])
            if routers:
                first_routers.add(routers[0])
        
        # 각 시작지점에서 첫 번째 라우터로 연결선 추가
        for source_ip in source_ips:
            for first_router in first_routers:
                edges.append({
                    'source': source_ip,
                    'target': first_router,
                    'value': 1,
                    'bleaching_points': [],
                    'type': 'source_connection'
                })
        
        # 라우터 간 연결선 추가
        for path in common_paths:
            routers = path.get('routers', [])
            for i in range(len(routers) - 1):
                edges.append({
                    'source': routers[i],
                    'target': routers[i + 1],
                    'value': path.get('frequency', 1),
                    'bleaching_points': path.get('bleaching_points', []),
                    'type': 'router_connection'
                })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'source_ips': source_ips
        }

# 전역 변수로 visualizer 인스턴스 생성
visualizer = None

@app.route('/')
def index():
    """메인 페이지"""
    return render_template('dashboard.html')

@app.route('/api/summary')
def api_summary():
    """요약 데이터 API"""
    return jsonify(visualizer.get_summary_data())

@app.route('/api/routers')
def api_routers():
    """라우터 통계 API"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(visualizer.get_router_statistics(limit))

@app.route('/api/domains')
def api_domains():
    """도메인 통계 API"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(visualizer.get_domain_statistics(limit))

@app.route('/api/paths')
def api_paths():
    """공통 경로 API"""
    limit = request.args.get('limit', 20, type=int)
    return jsonify(visualizer.get_common_paths(limit))

@app.route('/api/topology')
def api_topology():
    """네트워크 토폴로지 API"""
    return jsonify(visualizer.get_network_topology_data())

@app.route('/api/top-bleaching')
def api_top_bleaching():
    """상위 bleaching 라우터 API"""
    return jsonify(visualizer.get_top_bleaching_routers())

@app.route('/api/most-common')
def api_most_common():
    """가장 자주 나타나는 라우터 API"""
    return jsonify(visualizer.get_most_common_routers())

@app.route('/dashboard')
def dashboard():
    """대시보드 페이지"""
    return render_template('dashboard.html')

@app.route('/topology')
def topology():
    """네트워크 토폴로지 페이지"""
    return render_template('topology.html')

@app.route('/routers')
def routers():
    """라우터 분석 페이지"""
    return render_template('routers.html')

@app.route('/domains')
def domains():
    """도메인 분석 페이지"""
    return render_template('domains.html')

@app.route('/paths')
def paths():
    """경로 분석 페이지"""
    return render_template('paths.html')

def create_templates():
    """HTML 템플릿 생성"""
    templates_dir = "templates"
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # 기본 레이아웃 템플릿
    layout_html = """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}트레이스루트 분석 대시보드{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    {% block extra_head %}{% endblock %}
    <style>
        .sidebar {
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .sidebar .nav-link {
            color: rgba(255,255,255,0.8);
            border-radius: 8px;
            margin: 2px 0;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            color: white;
            background-color: rgba(255,255,255,0.1);
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .chart-container {
            position: relative;
            height: 400px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="position-sticky pt-3">
                    <div class="text-center mb-4">
                        <h4 class="text-white"><i class="fas fa-network-wired"></i> ECN 분석</h4>
                    </div>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link" href="/dashboard">
                                <i class="fas fa-tachometer-alt"></i> 대시보드
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/topology">
                                <i class="fas fa-project-diagram"></i> 네트워크 토폴로지
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/routers">
                                <i class="fas fa-server"></i> 라우터 분석
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/domains">
                                <i class="fas fa-globe"></i> 도메인 분석
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/paths">
                                <i class="fas fa-route"></i> 경로 분석
                            </a>
                        </li>
                    </ul>
                </div>
            </nav>

            <!-- Main content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="pt-3 pb-2 mb-3">
                    {% block content %}{% endblock %}
                </div>
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>"""
    
    with open(os.path.join(templates_dir, "layout.html"), 'w', encoding='utf-8') as f:
        f.write(layout_html)
    
    # 대시보드 템플릿
    dashboard_html = """{% extends "layout.html" %}

{% block title %}대시보드 - 트레이스루트 분석{% endblock %}

{% block content %}
<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
    <h1 class="h2">ECN Bleaching 분석 대시보드</h1>
</div>

<!-- 통계 카드들 -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card stat-card">
            <div class="card-body text-center">
                <h5 class="card-title">총 도메인</h5>
                <h2 id="total-domains">-</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card stat-card">
            <div class="card-body text-center">
                <h5 class="card-title">총 라우터</h5>
                <h2 id="total-routers">-</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card stat-card">
            <div class="card-body text-center">
                <h5 class="card-title">Bleaching 발생</h5>
                <h2 id="total-bleaching">-</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card stat-card">
            <div class="card-body text-center">
                <h5 class="card-title">공통 경로</h5>
                <h2 id="total-paths">-</h2>
            </div>
        </div>
    </div>
</div>

<!-- 차트들 -->
<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>ECN Bleaching 발생률</h5>
            </div>
            <div class="card-body">
                <div class="chart-container">
                    <canvas id="bleachingChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>라우터별 Bleaching 발생</h5>
            </div>
            <div class="card-body">
                <div class="chart-container">
                    <canvas id="routerChart"></canvas>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5>상위 Bleaching 라우터</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>IP 주소</th>
                                <th>총 발생 횟수</th>
                                <th>Bleaching 횟수</th>
                                <th>Bleaching 비율</th>
                                <th>평균 홉 위치</th>
                            </tr>
                        </thead>
                        <tbody id="top-bleaching-table">
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// 대시보드 데이터 로드
async function loadDashboardData() {
    try {
        const [summary, topBleaching] = await Promise.all([
            fetch('/api/summary').then(r => r.json()),
            fetch('/api/top-bleaching').then(r => r.json())
        ]);
        
        // 통계 카드 업데이트
        document.getElementById('total-domains').textContent = summary.total_domains || 0;
        document.getElementById('total-routers').textContent = summary.total_routers || 0;
        document.getElementById('total-bleaching').textContent = summary.total_bleaching_incidents || 0;
        document.getElementById('total-paths').textContent = summary.total_common_paths || 0;
        
        // 상위 bleaching 라우터 테이블 업데이트
        const tableBody = document.getElementById('top-bleaching-table');
        tableBody.innerHTML = '';
        
        topBleaching.slice(0, 10).forEach(router => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${router.ip}</td>
                <td>${router.total_occurrences}</td>
                <td>${router.bleaching_count}</td>
                <td>${(router.bleaching_rate * 100).toFixed(2)}%</td>
                <td>${router.avg_hop_position.toFixed(1)}</td>
            `;
            tableBody.appendChild(row);
        });
        
        // 차트 생성
        createBleachingChart(summary);
        createRouterChart(topBleaching);
        
    } catch (error) {
        console.error('데이터 로드 실패:', error);
    }
}

function createBleachingChart(summary) {
    const ctx = document.getElementById('bleachingChart').getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Bleaching 발생', '정상'],
            datasets: [{
                data: [
                    summary.total_bleaching_incidents || 0,
                    (summary.total_domains || 0) - (summary.total_bleaching_incidents || 0)
                ],
                backgroundColor: ['#ff6b6b', '#4ecdc4']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function createRouterChart(routers) {
    const ctx = document.getElementById('routerChart').getContext('2d');
    const top10 = routers.slice(0, 10);
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: top10.map(r => r.ip.substring(0, 15) + '...'),
            datasets: [{
                label: 'Bleaching 횟수',
                data: top10.map(r => r.bleaching_count),
                backgroundColor: '#667eea'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// 페이지 로드 시 데이터 로드
document.addEventListener('DOMContentLoaded', loadDashboardData);
</script>
{% endblock %}"""
    
    with open(os.path.join(templates_dir, "dashboard.html"), 'w', encoding='utf-8') as f:
        f.write(dashboard_html)
    
    # 네트워크 토폴로지 템플릿
    topology_html = """{% extends "layout.html" %}

{% block title %}네트워크 토폴로지 - 트레이스루트 분석{% endblock %}

{% block extra_head %}
<style>
    #topology-container {
        width: 100%;
        height: 600px;
        border: 1px solid #ddd;
        border-radius: 8px;
    }
    .node {
        stroke: #fff;
        stroke-width: 2px;
    }
    .link {
        stroke: #999;
        stroke-opacity: 0.6;
    }
    .link.bleaching {
        stroke: #ff6b6b;
        stroke-width: 3px;
    }
</style>
{% endblock %}

{% block content %}
<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
    <h1 class="h2">네트워크 토폴로지 시각화</h1>
</div>

<div class="row">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5>라우터 연결 관계</h5>
                <small class="text-muted">노드 크기는 bleaching 발생률에 비례, 빨간색 링크는 bleaching 발생 지점</small>
            </div>
            <div class="card-body">
                <div id="topology-container"></div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
let simulation;

async function loadTopologyData() {
    try {
        const data = await fetch('/api/topology').then(r => r.json());
        createTopologyVisualization(data);
    } catch (error) {
        console.error('토폴로지 데이터 로드 실패:', error);
    }
}

function createTopologyVisualization(data) {
    const container = document.getElementById('topology-container');
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    // SVG 생성
    const svg = d3.select(container)
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // 시뮬레이션 설정
    simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(data.edges).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2));
    
    // 링크 그리기
    const link = svg.append('g')
        .selectAll('line')
        .data(data.edges)
        .enter().append('line')
        .attr('class', d => {
            const bleachingPoints = d.bleaching_points || [];
            return bleachingPoints.includes(d.source.id || d.source) || 
                   bleachingPoints.includes(d.target.id || d.target) ? 'link bleaching' : 'link';
        })
        .attr('stroke-width', d => Math.sqrt(d.value));
    
    // 노드 그리기
    const node = svg.append('g')
        .selectAll('circle')
        .data(data.nodes)
        .enter().append('circle')
        .attr('class', 'node')
        .attr('r', d => Math.max(5, d.bleaching_rate * 50))
        .attr('fill', d => d.bleaching_rate > 0 ? '#ff6b6b' : '#4ecdc4')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));
    
    // 툴팁 추가
    node.append('title')
        .text(d => `IP: ${d.id}\\nBleaching Rate: ${(d.bleaching_rate * 100).toFixed(2)}%\\nOccurrences: ${d.occurrences}`);
    
    // 시뮬레이션 업데이트
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
}

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

// 페이지 로드 시 토폴로지 로드
document.addEventListener('DOMContentLoaded', loadTopologyData);
</script>
{% endblock %}"""
    
    with open(os.path.join(templates_dir, "topology.html"), 'w', encoding='utf-8') as f:
        f.write(topology_html)
    
    # 라우터 분석 템플릿
    routers_html = """{% extends "layout.html" %}

{% block title %}라우터 분석 - 트레이스루트 분석{% endblock %}

{% block content %}
<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
    <h1 class="h2">라우터별 ECN Bleaching 분석</h1>
</div>

<div class="row mb-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5>라우터 통계</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped" id="routers-table">
                        <thead>
                            <tr>
                                <th>IP 주소</th>
                                <th>총 발생 횟수</th>
                                <th>Bleaching 횟수</th>
                                <th>Bleaching 비율</th>
                                <th>평균 홉 위치</th>
                                <th>평균 응답시간</th>
                                <th>성공률</th>
                                <th>도달 도메인 수</th>
                            </tr>
                        </thead>
                        <tbody>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
async function loadRouterData() {
    try {
        const routers = await fetch('/api/routers?limit=100').then(r => r.json());
        updateRouterTable(routers);
    } catch (error) {
        console.error('라우터 데이터 로드 실패:', error);
    }
}

function updateRouterTable(routers) {
    const tableBody = document.querySelector('#routers-table tbody');
    tableBody.innerHTML = '';
    
    routers.forEach(router => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${router.ip}</td>
            <td>${router.total_occurrences}</td>
            <td>${router.bleaching_count}</td>
            <td>
                <div class="progress" style="height: 20px;">
                    <div class="progress-bar bg-danger" style="width: ${router.bleaching_rate * 100}%">
                        ${(router.bleaching_rate * 100).toFixed(1)}%
                    </div>
                </div>
            </td>
            <td>${router.avg_hop_position.toFixed(1)}</td>
            <td>${router.avg_response_time.toFixed(3)}s</td>
            <td>${(router.success_rate * 100).toFixed(1)}%</td>
            <td>${router.domains_reached_count}</td>
        `;
        tableBody.appendChild(row);
    });
}

document.addEventListener('DOMContentLoaded', loadRouterData);
</script>
{% endblock %}"""
    
    with open(os.path.join(templates_dir, "routers.html"), 'w', encoding='utf-8') as f:
        f.write(routers_html)
    
    # 도메인 분석 템플릿
    domains_html = """{% extends "layout.html" %}

{% block title %}도메인 분석 - 트레이스루트 분석{% endblock %}

{% block content %}
<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
    <h1 class="h2">도메인별 ECN Bleaching 분석</h1>
</div>

<div class="row mb-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5>도메인 통계</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped" id="domains-table">
                        <thead>
                            <tr>
                                <th>도메인</th>
                                <th>IP 주소</th>
                                <th>성공한 홉</th>
                                <th>총 홉</th>
                                <th>Bleaching 횟수</th>
                                <th>Bleaching 비율</th>
                                <th>실행 시간</th>
                                <th>평균 응답시간</th>
                            </tr>
                        </thead>
                        <tbody>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
async function loadDomainData() {
    try {
        const domains = await fetch('/api/domains?limit=100').then(r => r.json());
        updateDomainTable(domains);
    } catch (error) {
        console.error('도메인 데이터 로드 실패:', error);
    }
}

function updateDomainTable(domains) {
    const tableBody = document.querySelector('#domains-table tbody');
    tableBody.innerHTML = '';
    
    domains.forEach(domain => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${domain.domain}</td>
            <td>${domain.ip}</td>
            <td>${domain.successful_hops}</td>
            <td>${domain.total_hops}</td>
            <td>${domain.bleaching_count}</td>
            <td>
                <div class="progress" style="height: 20px;">
                    <div class="progress-bar bg-warning" style="width: ${domain.bleaching_rate * 100}%">
                        ${(domain.bleaching_rate * 100).toFixed(1)}%
                    </div>
                </div>
            </td>
            <td>${domain.execution_time.toFixed(2)}s</td>
            <td>${domain.avg_response_time.toFixed(3)}s</td>
        `;
        tableBody.appendChild(row);
    });
}

document.addEventListener('DOMContentLoaded', loadDomainData);
</script>
{% endblock %}"""
    
    with open(os.path.join(templates_dir, "domains.html"), 'w', encoding='utf-8') as f:
        f.write(domains_html)
    
    # 경로 분석 템플릿
    paths_html = """{% extends "layout.html" %}

{% block title %}경로 분석 - 트레이스루트 분석{% endblock %}

{% block content %}
<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
    <h1 class="h2">공통 경로 분석</h1>
</div>

<div class="row mb-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-header">
                <h5>공통 경로 목록</h5>
            </div>
            <div class="card-body">
                <div id="paths-container">
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
async function loadPathsData() {
    try {
        const paths = await fetch('/api/paths?limit=50').then(r => r.json());
        updatePathsDisplay(paths);
    } catch (error) {
        console.error('경로 데이터 로드 실패:', error);
    }
}

function updatePathsDisplay(paths) {
    const container = document.getElementById('paths-container');
    container.innerHTML = '';
    
    paths.forEach((path, index) => {
        const pathCard = document.createElement('div');
        pathCard.className = 'card mb-3';
        pathCard.innerHTML = `
            <div class="card-header">
                <h6>경로 ${index + 1} (발생 빈도: ${path.frequency}회)</h6>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-8">
                        <h6>라우터 경로:</h6>
                        <div class="d-flex flex-wrap">
                            ${path.routers.map((router, i) => `
                                <span class="badge bg-primary me-1 mb-1">
                                    ${i + 1}. ${router}
                                </span>
                            `).join('')}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <h6>Bleaching 포인트:</h6>
                        ${path.bleaching_points.length > 0 ? 
                            path.bleaching_points.map(ip => `
                                <span class="badge bg-danger me-1 mb-1">${ip}</span>
                            `).join('') : 
                            '<span class="text-muted">없음</span>'
                        }
                        <br><br>
                        <h6>대표 도메인:</h6>
                        ${path.representative_domains.map(domain => `
                            <span class="badge bg-secondary me-1 mb-1">${domain}</span>
                        `).join('')}
                    </div>
                </div>
                <div class="row mt-3">
                    <div class="col-md-6">
                        <small class="text-muted">평균 홉 수: ${path.avg_hops.toFixed(1)}</small>
                    </div>
                    <div class="col-md-6">
                        <small class="text-muted">평균 Bleaching 수: ${path.avg_bleaching_count.toFixed(1)}</small>
                    </div>
                </div>
            </div>
        `;
        container.appendChild(pathCard);
    });
}

document.addEventListener('DOMContentLoaded', loadPathsData);
</script>
{% endblock %}"""
    
    with open(os.path.join(templates_dir, "paths.html"), 'w', encoding='utf-8') as f:
        f.write(paths_html)

def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='트레이스루트 결과 웹 시각화 도구 v2')
    parser.add_argument('--analysis-file', default='analysis_results_v2.json', 
                       help='분석 결과 파일 경로 (기본값: analysis_results_v2.json)')
    parser.add_argument('--port', type=int, default=5000, help='서버 포트 (기본값: 5000)')
    parser.add_argument('--host', default='127.0.0.1', help='서버 호스트 (기본값: 127.0.0.1)')
    parser.add_argument('--debug', action='store_true', help='디버그 모드 활성화')
    
    args = parser.parse_args()
    
    # 템플릿 생성 (처음 실행시에만)
    if not os.path.exists('templates'):
        create_templates()
        logger.info("템플릿 파일들이 생성되었습니다.")
    else:
        logger.info("기존 템플릿 파일들을 사용합니다.")
    
    # 전역 visualizer 초기화
    global visualizer
    visualizer = WebVisualizer(args.analysis_file)
    
    logger.info(f"웹 시각화 서버 시작: http://{args.host}:{args.port}")
    logger.info("사용 가능한 페이지:")
    logger.info("  - /dashboard : 메인 대시보드")
    logger.info("  - /topology : 네트워크 토폴로지")
    logger.info("  - /routers : 라우터 분석")
    logger.info("  - /domains : 도메인 분석")
    logger.info("  - /paths : 경로 분석")
    
    # Flask 앱 실행
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main() 