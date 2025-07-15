#!/usr/bin/env python3
import csv
import sys
import time
import logging
from datetime import date
import os
from collections import defaultdict

# 로깅 설정
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def get_ip_class(ip_address, class_type='B'):
    """
    IP 주소에서 A 클래스 또는 B 클래스를 추출
    A 클래스: 첫 번째 옥텟 (예: 192.168.1.1 -> 192)
    B 클래스: 첫 번째 + 두 번째 옥텟 (예: 192.168.1.1 -> 192.168)
    """
    try:
        octets = ip_address.split('.')
        if len(octets) != 4:
            return None
        
        if class_type.upper() == 'A':
            return octets[0]
        elif class_type.upper() == 'B':
            return f"{octets[0]}.{octets[1]}"
        else:
            raise ValueError("class_type은 'A' 또는 'B'여야 합니다.")
    
    except Exception as e:
        logging.error(f"IP 주소 {ip_address} 파싱 중 오류: {e}")
        return None

def count_total_lines(file_path):
    """
    파일의 총 라인 수를 계산 (헤더 제외)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return sum(1 for line in f) - 1  # 헤더 제외
    except Exception as e:
        logging.error(f"파일 라인 수 계산 중 오류: {e}")
        return 0

def deduplicate_ip_by_class(input_file, output_file, class_type='B'):
    """
    IP 주소 리스트에서 A 또는 B 클래스를 기준으로 중복 제거
    각 클래스에서 첫 번째 IP만 유지
    """
    ip_groups = defaultdict(list)
    total_ips = 0
    unique_ips = 0
    processed_ips = 0
    
    # 총 라인 수 계산
    total_lines = count_total_lines(input_file)
    if total_lines == 0:
        logging.error("파일이 비어있거나 읽을 수 없습니다.")
        return False
    
    logging.info(f"IP 중복 제거 시작: {input_file} (기준: {class_type} 클래스)")
    logging.info(f"총 처리할 IP 수: {total_lines:,}개")
    print(f"\n{'='*60}")
    print(f"진행상황: 0% | 처리된 IP: 0/{total_lines:,} | 중복 제거된 IP: 0개 | 남은 IP: 0개")
    
    # CSV 파일 읽기
    try:
        with open(input_file, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            for row_num, row in enumerate(reader, 1):
                processed_ips += 1
                
                try:
                    number = row.get('Number', str(row_num))
                    domain = row.get('Domain', '')
                    ip_address = row.get('IP_Address', '')
                    
                    # IP 주소가 유효하지 않은 경우 건너뛰기
                    if not ip_address or ip_address in ['N/A', 'INVALID_FORMAT'] or ip_address.startswith('ERROR:'):
                        continue
                    
                    # IP 클래스 추출
                    ip_class = get_ip_class(ip_address, class_type)
                    if ip_class is None:
                        continue
                    
                    # 해당 클래스에 IP 추가
                    ip_groups[ip_class].append({
                        'number': number,
                        'domain': domain,
                        'ip_address': ip_address,
                        'ip_class': ip_class
                    })
                    
                    # 진행상황 표시 (100개마다 또는 5%마다)
                    if processed_ips % 100 == 0 or processed_ips % max(1, total_lines // 20) == 0:
                        progress_percent = (processed_ips / total_lines) * 100
                        print(f"\r진행상황: {progress_percent:.1f}% | 처리된 IP: {processed_ips:,}/{total_lines:,} | 중복 제거된 IP: {processed_ips - len(ip_groups):,}개 | 남은 IP: {len(ip_groups):,}개", end='', flush=True)
                        
                except Exception as e:
                    logging.error(f"라인 {row_num} 처리 중 오류: {e}")
                    continue
    
    except FileNotFoundError:
        logging.error(f"입력 파일을 찾을 수 없습니다: {input_file}")
        return False
    except Exception as e:
        logging.error(f"파일 읽기 중 오류 발생: {e}")
        return False
    
    print(f"\n{'='*60}")
    logging.info("중복 제거 처리 완료. 결과 정리 중...")
    
    # 각 클래스에서 첫 번째 IP만 선택
    unique_results = []
    duplicate_count = 0
    
    for ip_class, ips in ip_groups.items():
        if ips:
            # 첫 번째 IP 선택
            first_ip = ips[0]
            unique_results.append(first_ip)
            unique_ips += 1
            
            # 중복된 IP 개수 계산
            if len(ips) > 1:
                duplicate_count += len(ips) - 1
    
    # 결과를 CSV 파일로 저장
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            # 헤더 추가
            writer.writerow(['Number', 'Domain', 'IP_Address', 'IP_Class'])
            # 데이터 작성
            for result in unique_results:
                writer.writerow([
                    result['number'],
                    result['domain'],
                    result['ip_address'],
                    result['ip_class']
                ])
        
        print(f"\n{'='*60}")
        logging.info(f"결과가 {output_file}에 저장되었습니다.")
        logging.info(f"📊 최종 통계:")
        logging.info(f"   총 처리된 IP: {processed_ips:,}개")
        logging.info(f"   중복 제거 후 IP: {unique_ips:,}개")
        logging.info(f"   제거된 중복 IP: {duplicate_count:,}개")
        logging.info(f"   중복 제거율: {(duplicate_count/processed_ips*100):.1f}%")
        logging.info(f"   유지율: {(unique_ips/processed_ips*100):.1f}%")
        
        return True
        
    except Exception as e:
        logging.error(f"CSV 파일 저장 중 오류 발생: {e}")
        return False

def analyze_ip_distribution(input_file):
    """
    IP 분포 분석 (선택적 기능)
    """
    class_counts = defaultdict(int)
    total_valid_ips = 0
    
    logging.info("IP 분포 분석 중...")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            for row in reader:
                ip_address = row.get('IP_Address', '')
                if ip_address and ip_address not in ['N/A', 'INVALID_FORMAT'] and not ip_address.startswith('ERROR:'):
                    ip_class = get_ip_class(ip_address, 'B')
                    if ip_class:
                        class_counts[ip_class] += 1
                        total_valid_ips += 1
        
        # 상위 10개 클래스 출력
        top_classes = sorted(class_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        logging.info(f"📈 IP 분포 분석 결과 (총 {total_valid_ips:,}개 유효 IP):")
        for i, (ip_class, count) in enumerate(top_classes, 1):
            percentage = (count / total_valid_ips) * 100
            logging.info(f"   {i:2d}. {ip_class}: {count:,}개 ({percentage:.1f}%)")
            
    except Exception as e:
        logging.error(f"IP 분포 분석 중 오류: {e}")

def main():
    if len(sys.argv) < 2:
        print("사용법: python deduplicate_ip_by_class.py <IP_리스트_CSV_파일> [클래스_타입]")
        print("클래스 타입: A (첫 번째 옥텟) 또는 B (첫 번째+두 번째 옥텟, 기본값)")
        print("예시: python deduplicate_ip_by_class.py ip_extracted_web_1000_20241201.csv B")
        sys.exit(1)
    
    input_file = sys.argv[1]
    class_type = sys.argv[2] if len(sys.argv) > 2 else 'B'
    
    if class_type.upper() not in ['A', 'B']:
        print("클래스 타입은 'A' 또는 'B'여야 합니다.")
        sys.exit(1)
    
    # 출력 파일명 생성
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    today = date.today().strftime("%Y%m%d")
    output_file = f"deduplicated_{base_name}_{class_type}class_{today}.csv"
    
    start_time = time.time()
    
    # IP 분포 분석 (선택적)
    analyze_ip_distribution(input_file)
    
    # 중복 제거 실행
    success = deduplicate_ip_by_class(input_file, output_file, class_type)
    
    if success:
        print(f"\n{'='*60}")
        print(f"✅ 중복 제거 완료!")
        print(f"📁 입력 파일: {input_file}")
        print(f"📁 출력 파일: {output_file}")
        print(f"🎯 기준 클래스: {class_type}")
        print(f"⏱️  처리 시간: {time.time() - start_time:.2f}초")
        print(f"{'='*60}")
    else:
        print("❌ 처리 중 오류가 발생했습니다.")
        sys.exit(1)

if __name__ == "__main__":
    main() 