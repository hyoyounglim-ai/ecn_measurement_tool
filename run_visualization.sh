#!/bin/bash

# 트레이스루트 ECN 분석 시각화 도구 실행 스크립트

echo "🌐 트레이스루트 ECN 분석 시각화 도구"
echo "=================================="

# 결과 디렉토리 확인
RESULTS_DIR=${1:-"traceroute"}
PORT=${2:-5000}

echo "📁 결과 디렉토리: $RESULTS_DIR"
echo "🌐 웹 서버 포트: $PORT"

# 결과 디렉토리 존재 확인
if [ ! -d "$RESULTS_DIR" ]; then
    echo "❌ 결과 디렉토리가 존재하지 않습니다: $RESULTS_DIR"
    echo "💡 먼저 트레이스루트를 실행하여 데이터를 수집하세요:"
    echo "   python traceroute_improved.py sample_ip_list.txt"
    exit 1
fi

# JSON 파일 존재 확인
JSON_COUNT=$(find "$RESULTS_DIR" -name "traceroute_*.json" | wc -l)
if [ "$JSON_COUNT" -eq 0 ]; then
    echo "❌ JSON 결과 파일이 없습니다."
    echo "💡 먼저 개선된 트레이스루트 도구로 데이터를 수집하세요."
    exit 1
fi

echo "✅ $JSON_COUNT개의 JSON 파일 발견"

# Python 환경 확인
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3가 설치되지 않았습니다."
    exit 1
fi

# 필요한 패키지 설치 확인
echo "📦 필요한 패키지 확인 중..."
python3 -c "import flask, networkx, matplotlib, pandas, numpy" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  필요한 패키지가 설치되지 않았습니다."
    echo "📥 설치 중..."
    pip3 install -r requirements_visualization.txt
fi

echo "🚀 웹 시각화 도구 시작 중..."
echo "🌐 브라우저에서 http://localhost:$PORT 접속"
echo "⏹️  중단하려면 Ctrl+C"

# 웹 애플리케이션 실행
python3 web_visualizer.py --results-dir "$RESULTS_DIR" --port "$PORT" 