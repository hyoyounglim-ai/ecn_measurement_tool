# 개선된 멀티스레드 트레이스루트 도구

## 개선사항

### 1. 성능 개선
- **멀티스레딩**: ThreadPoolExecutor를 사용하여 여러 도메인을 동시에 처리
- **진행률 표시**: tqdm을 사용한 실시간 진행률 표시
- **최적화된 타임아웃**: 각 홉별 개별 타임아웃 설정

### 2. 코드 구조 개선
- **모듈화**: 클래스 기반 구조로 변경
- **데이터 클래스**: 구조화된 데이터 저장
- **에러 처리**: 강화된 예외 처리 및 로깅

### 3. 결과 저장 체계화
- **JSON 형식**: 구조화된 JSON 결과 저장
- **개별 파일**: 각 도메인별 개별 결과 파일
- **요약 파일**: 전체 통계 및 요약 정보
- **메타데이터**: 실행 환경 및 설정 정보 포함

### 4. 디버깅 및 모니터링
- **상세 로깅**: 파일 및 콘솔 동시 출력
- **진행률 표시**: 실시간 진행 상황 확인
- **통계 정보**: 성공률, ECN bleaching 발생률 등

## 설치

```bash
pip install -r requirements_improved.txt
```

## 사용법

### 기본 사용법
```bash
python traceroute_improved.py ip_list.txt
```

### 고급 옵션
```bash
python traceroute_improved.py ip_list.txt \
    --workers 10 \
    --timeout 0.5 \
    --max-hops 25 \
    --output-dir results
```

### 매개변수 설명
- `ip_list`: IP/도메인 리스트 파일 (CSV 형식: ID,Domain)
- `--workers`: 동시 실행할 워커 수 (기본값: 5)
- `--timeout`: 패킷 타임아웃 (기본값: 0.3초)
- `--max-hops`: 최대 홉 수 (기본값: 30)
- `--output-dir`: 결과 저장 디렉토리 (기본값: traceroute)

## 입력 파일 형식

```
1,google.com
2,facebook.com
3,amazon.com
```

## 출력 파일

### 개별 결과 파일
`traceroute_{domain}_{ip}_{timestamp}.json`
```json
{
  "target_domain": "google.com",
  "target_ip": "142.250.191.78",
  "source_ip": "192.168.1.100",
  "timestamp": "2024-01-15T10:30:45.123456",
  "total_hops": 15,
  "successful_hops": 12,
  "bleaching_count": 2,
  "hops": [...],
  "execution_time": 3.45,
  "metadata": {...}
}
```

### 요약 파일
`traceroute_summary_{timestamp}.json`
```json
{
  "summary": {
    "total_targets": 100,
    "successful_traceroutes": 85,
    "total_bleaching_incidents": 23,
    "average_execution_time": 4.2,
    "timestamp": "20240115_103045",
    "source_ip": "192.168.1.100"
  },
  "targets": [...]
}
```

## 로그 파일

- `traceroute.log`: 상세한 실행 로그
- 콘솔 출력: 실시간 진행 상황 및 통계

## 성능 비교

| 항목 | 기존 버전 | 개선 버전 | 개선율 |
|------|-----------|-----------|--------|
| 단일 도메인 처리 | 순차 처리 | 멀티스레드 | 3-5배 빠름 |
| 진행률 표시 | 없음 | 실시간 표시 | - |
| 결과 저장 | 텍스트 | JSON 구조화 | - |
| 에러 처리 | 기본 | 강화된 처리 | - |

## 주의사항

1. **관리자 권한**: Scapy 사용을 위해 관리자 권한이 필요할 수 있습니다.
2. **네트워크 부하**: 멀티스레딩으로 인한 네트워크 부하 증가 가능
3. **방화벽**: 일부 네트워크에서 ICMP 패킷이 차단될 수 있습니다.

## 문제 해결

### 일반적인 오류
1. **권한 오류**: `sudo python traceroute_improved.py ...`
2. **패키지 누락**: `pip install -r requirements_improved.txt`
3. **네트워크 오류**: 타임아웃 값 조정

### 성능 튜닝
- 워커 수 조정: 네트워크 환경에 따라 3-10개 권장
- 타임아웃 조정: 네트워크 지연에 따라 0.2-1.0초 권장
- 최대 홉 수: 일반적으로 15-30개 권장 