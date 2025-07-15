# 트레이스루트 ECN 분석 시각화 도구

## 개요

이 도구는 트레이스루트 결과를 분석하여 네트워크 경로에서의 ECN Bleaching 패턴을 시각화하는 웹 애플리케이션입니다. 중복 경로와 대표성 있는 라우터들을 분석하여 네트워크 토폴로지를 시각적으로 표현합니다.

## 주요 기능

### 1. 라우터 분석 🔍
- **ECN Bleaching 통계**: 각 라우터별 ECN 값 변경 빈도 분석
- **사용 빈도 분석**: 가장 자주 나타나는 라우터 식별
- **대표성 분석**: 여러 경로에서 공통으로 사용되는 라우터 발견

### 2. 경로 분석 🛣️
- **공통 경로 발견**: 여러 도메인에서 공통으로 사용되는 경로 식별
- **경로 빈도 분석**: 각 경로의 사용 빈도 계산
- **Bleaching 포인트 매핑**: 경로 내에서 ECN 값이 변경되는 지점 표시

### 3. 네트워크 토폴로지 시각화 🌍
- **인터랙티브 그래프**: D3.js 기반 네트워크 그래프
- **라우터별 색상 코딩**: ECN Bleaching 비율에 따른 색상 구분
- **노드 크기**: 라우터 사용 빈도에 따른 크기 조정
- **엣지 두께**: 경로 사용 빈도에 따른 선 두께 조정

### 4. 대시보드 📊
- **실시간 통계**: 분석된 도메인, 라우터, 경로 수 표시
- **차트 시각화**: Chart.js 기반 차트
- **상세 테이블**: 라우터별 상세 정보 표시

## 설치

```bash
# 기존 요구사항 설치
pip install -r requirements_improved.txt

# 시각화 도구 요구사항 설치
pip install -r requirements_visualization.txt
```

## 사용법

### 1. 트레이스루트 실행
먼저 개선된 트레이스루트 도구로 데이터를 수집합니다:

```bash
python traceroute_improved.py sample_ip_list.txt --workers 5
```

### 2. 시각화 도구 실행
수집된 결과를 분석하고 웹 대시보드를 실행합니다:

```bash
python web_visualizer.py --results-dir traceroute --port 5000
```

### 3. 웹 브라우저에서 확인
브라우저에서 `http://localhost:5000`에 접속하여 대시보드를 확인합니다.

## 대시보드 구성

### 메인 통계 카드
- **분석된 도메인**: 총 분석된 도메인 수
- **발견된 라우터**: 고유한 라우터 수
- **공통 경로**: 여러 도메인에서 공통으로 사용되는 경로 수
- **ECN Bleaching 발생**: 총 ECN 값 변경 발생 횟수

### ECN Bleaching 차트
- 상위 5개 라우터의 ECN Bleaching 발생 횟수를 막대 차트로 표시
- 빨간색으로 강조하여 문제가 되는 라우터를 쉽게 식별

### 라우터 사용 빈도 차트
- 가장 자주 나타나는 라우터들을 도넛 차트로 표시
- 네트워크에서 핵심 역할을 하는 라우터 식별

### 상위 ECN Bleaching 라우터 테이블
- IP 주소, Bleaching 횟수, 총 발생 횟수, Bleaching 비율, 평균 홉 수 표시
- 색상 코딩으로 Bleaching 비율 구분:
  - 🔴 높음 (>50%): 빨간색
  - 🟡 중간 (20-50%): 노란색
  - 🟢 낮음 (<20%): 초록색

### 공통 경로 분석
- 여러 도메인에서 공통으로 사용되는 경로들을 표시
- 각 경로의 라우터 순서, Bleaching 포인트, 대표 도메인 정보 제공

### 네트워크 토폴로지 그래프
- **노드**: 라우터 (크기는 사용 빈도에 비례)
- **색상**: ECN Bleaching 비율에 따른 색상 구분
  - 🔴 빨간색: 높은 Bleaching 비율 (>50%)
  - 🟡 노란색: 중간 Bleaching 비율 (20-50%)
  - 🟢 초록색: 낮은 Bleaching 비율 (<20%)
- **엣지**: 라우터 간 연결 (두께는 사용 빈도에 비례)
- **인터랙션**: 드래그로 노드 이동, 호버로 상세 정보 표시

## 분석 예시

### 시나리오 1: ISP 경계 라우터 분석
```
도메인 A, B, C → 공통 경로: R1 → R2 → R3 → R4
ECN Bleaching 발생: R2에서 80% 비율로 발생
결론: R2는 ISP 경계 라우터로 ECN 정책이 엄격함
```

### 시나리오 2: 대표성 있는 라우터 발견
```
라우터 R5: 50개 도메인 중 45개에서 발견
ECN Bleaching 비율: 5%
결론: R5는 핵심 백본 라우터로 ECN 정책이 관대함
```

### 시나리오 3: 경로 최적화 기회
```
경로 P1: 10개 도메인에서 공통 사용
Bleaching 포인트: R7, R9
결론: R7, R9를 우회하는 경로로 최적화 가능
```

## 고급 사용법

### 커스텀 분석
```python
from traceroute_analyzer import TracerouteAnalyzer

# 분석기 생성
analyzer = TracerouteAnalyzer('traceroute')

# 결과 로드 및 분석
analyzer.load_results()
analyzer.analyze_routers()
analyzer.find_common_paths()

# 상위 Bleaching 라우터 조회
top_routers = analyzer.get_top_bleaching_routers(10)

# 네트워크 그래프 생성
G = analyzer.generate_network_graph()

# 결과 내보내기
analyzer.export_analysis_results('custom_analysis.json')
```

### API 엔드포인트
웹 애플리케이션은 다음 API 엔드포인트를 제공합니다:

- `GET /api/summary`: 전체 통계 요약
- `GET /api/routers`: 모든 라우터 정보
- `GET /api/paths`: 공통 경로 정보
- `GET /api/network-graph`: 네트워크 그래프 데이터

## 성능 최적화

### 대용량 데이터 처리
- **청크 처리**: 대용량 결과 파일을 청크 단위로 처리
- **메모리 최적화**: 필요한 데이터만 메모리에 로드
- **캐싱**: 분석 결과를 캐시하여 반복 분석 시간 단축

### 시각화 최적화
- **노드 필터링**: 중요도가 낮은 노드 제외
- **엣지 임계값**: 사용 빈도가 낮은 연결 제외
- **렌더링 최적화**: D3.js 렌더링 성능 최적화

## 문제 해결

### 일반적인 문제
1. **메모리 부족**: 대용량 데이터 처리 시 메모리 부족
   - 해결: 청크 단위 처리 또는 샘플링 사용

2. **그래프 렌더링 느림**: 노드가 너무 많은 경우
   - 해결: 중요도 임계값 조정으로 노드 수 제한

3. **브라우저 호환성**: 일부 브라우저에서 차트가 표시되지 않음
   - 해결: 최신 브라우저 사용 권장

### 디버깅
```bash
# 상세 로그 활성화
export PYTHONPATH=.
python web_visualizer.py --results-dir traceroute --debug

# 분석 결과 확인
python -c "
from traceroute_analyzer import TracerouteAnalyzer
a = TracerouteAnalyzer('traceroute')
print(f'로드된 결과: {len(a.load_results())}개')
"
```

## 확장 가능성

### 추가 기능
- **지리적 시각화**: 라우터 위치 정보 추가
- **시간별 분석**: 시간대별 ECN Bleaching 패턴 분석
- **AS 정보**: AS 번호 및 ISP 정보 표시
- **경고 시스템**: Bleaching 비율이 높은 라우터 자동 감지

### 데이터 소스 확장
- **다양한 프로토콜**: TCP, ICMP 등 다양한 프로토콜 지원
- **실시간 모니터링**: 실시간 트레이스루트 결과 분석
- **외부 API 연동**: IP 정보, AS 정보 등 외부 API 연동

이 도구를 통해 네트워크 인프라의 ECN 정책을 체계적으로 분석하고 시각화할 수 있습니다! 🚀 