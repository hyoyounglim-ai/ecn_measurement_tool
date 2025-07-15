#!/usr/bin/env python3
import socket
import csv
import sys
import time
import logging
from datetime import date
import os
import json

# 로깅 설정
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

def extract_ip_from_domain(domain):
    """
    도메인에서 IP 주소를 추출하는 함수
    """
    try:
        ip_addr = socket.gethostbyname(domain)
        return ip_addr
    except socket.gaierror:
        logging.warning(f"도메인 {domain}에서 IP 주소를 찾을 수 없습니다.")
        return None
    except Exception as e:
        logging.error(f"도메인 {domain} 처리 중 오류 발생: {e}")
        return None

def count_total_lines(file_path):
    """
    파일의 총 라인 수를 계산
    """
    try:
        with open(file_path, 'r') as f:
            return sum(1 for line in f if line.strip())  # 빈 줄 제외
    except Exception as e:
        logging.error(f"파일 라인 수 계산 중 오류: {e}")
        return 0

def load_progress(progress_file):
    """
    진행상황 파일에서 이전 진행상황 로드
    """
    try:
        if os.path.exists(progress_file):
            with open(progress_file, 'r') as f:
                progress_data = json.load(f)
                logging.info(f"이전 진행상황 발견: {progress_data['processed_count']}개 처리됨")
                return progress_data
    except Exception as e:
        logging.error(f"진행상황 파일 로드 중 오류: {e}")
    return None

def save_progress(progress_file, processed_count, success_count, results):
    """
    진행상황을 파일에 저장
    """
    try:
        progress_data = {
            'processed_count': processed_count,
            'success_count': success_count,
            'timestamp': time.time()
        }
        with open(progress_file, 'w') as f:
            json.dump(progress_data, f)
    except Exception as e:
        logging.error(f"진행상황 저장 중 오류: {e}")

def save_results_to_csv(output_file, results, is_temp=False):
    """
    결과를 CSV 파일에 저장
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Number', 'Domain', 'IP_Address'])
            writer.writerows(results)
        
        if is_temp:
            logging.info(f"임시 결과 저장 완료: {output_file}")
        else:
            logging.info(f"최종 결과 저장 완료: {output_file}")
        return True
    except Exception as e:
        logging.error(f"CSV 파일 저장 중 오류: {e}")
        return False

def process_domain_file(input_file, output_file):
    """
    도메인 리스트 파일을 읽어서 IP 주소를 추출하고 CSV 파일로 저장
    """
    # 파일명 생성
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    progress_file = f"progress_{base_name}.json"
    temp_file = f"temp_{base_name}.csv"
    
    # 이전 진행상황 확인
    progress_data = load_progress(progress_file)
    start_line = 0
    processed_count = 0
    success_count = 0
    results = []
    
    if progress_data:
        start_line = progress_data['processed_count']
        processed_count = progress_data['processed_count']
        success_count = progress_data['success_count']
        
        # 임시 파일에서 이전 결과 로드
        if os.path.exists(temp_file):
            try:
                with open(temp_file, 'r', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        results.append([row['Number'], row['Domain'], row['IP_Address']])
                logging.info(f"임시 파일에서 {len(results)}개 결과 로드됨")
            except Exception as e:
                logging.error(f"임시 파일 로드 중 오류: {e}")
                results = []
    
    # 총 라인 수 계산
    total_lines = count_total_lines(input_file)
    if total_lines == 0:
        logging.error("파일이 비어있거나 읽을 수 없습니다.")
        return False
    
    logging.info(f"도메인 파일 처리 시작: {input_file}")
    logging.info(f"총 처리할 도메인 수: {total_lines:,}개")
    if start_line > 0:
        logging.info(f"이전 진행상황부터 재시작: {start_line:,}번째 라인부터")
    print(f"\n{'='*60}")
    print(f"진행상황: {(processed_count/total_lines*100):.1f}% | 처리된 도메인: {processed_count:,}/{total_lines:,} | 성공: {success_count:,}개 | 실패: {processed_count-success_count:,}개")
    
    try:
        with open(input_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                # 이전에 처리된 라인은 건너뛰기
                if line_num <= start_line:
                    continue
                
                line = line.strip()
                if not line:  # 빈 줄 건너뛰기
                    continue
                
                try:
                    # CSV 형식으로 파싱 (번호,도메인)
                    parts = line.split(',')
                    if len(parts) >= 2:
                        number = parts[0].strip()
                        domain = parts[1].strip()
                        
                        # IP 주소 추출
                        ip_addr = extract_ip_from_domain(domain)
                        
                        if ip_addr:
                            results.append([number, domain, ip_addr])
                            success_count += 1
                        else:
                            results.append([number, domain, "N/A"])
                    else:
                        results.append([line_num, line, "INVALID_FORMAT"])
                    
                    processed_count += 1
                    
                    # 1000개마다 임시 저장 및 진행상황 저장
                    if processed_count % 1000 == 0:
                        save_results_to_csv(temp_file, results, is_temp=True)
                        save_progress(progress_file, processed_count, success_count, results)
                        logging.info(f"임시 저장 완료: {processed_count}개 처리됨")
                    
                    # 진행상황 표시 (100개마다 또는 5%마다)
                    if processed_count % 100 == 0 or processed_count % max(1, total_lines // 20) == 0:
                        progress_percent = (processed_count / total_lines) * 100
                        failed_count = processed_count - success_count
                        print(f"\r진행상황: {progress_percent:.1f}% | 처리된 도메인: {processed_count:,}/{total_lines:,} | 성공: {success_count:,}개 | 실패: {failed_count:,}개", end='', flush=True)
                        
                except Exception as e:
                    logging.error(f"라인 {line_num} 처리 중 오류: {e}")
                    results.append([line_num, line, f"ERROR: {str(e)}"])
                    processed_count += 1
    
    except FileNotFoundError:
        logging.error(f"입력 파일을 찾을 수 없습니다: {input_file}")
        return False
    except Exception as e:
        logging.error(f"파일 읽기 중 오류 발생: {e}")
        return False
    
    # 최종 결과 저장
    print(f"\n{'='*60}")
    logging.info("IP 추출 완료. 최종 결과 저장 중...")
    
    if save_results_to_csv(output_file, results):
        # 임시 파일과 진행상황 파일 삭제
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            if os.path.exists(progress_file):
                os.remove(progress_file)
            logging.info("임시 파일 및 진행상황 파일 삭제 완료")
        except Exception as e:
            logging.warning(f"임시 파일 삭제 중 오류: {e}")
        
        print(f"\n{'='*60}")
        logging.info(f"📊 최종 통계:")
        logging.info(f"   총 처리된 도메인: {processed_count:,}개")
        logging.info(f"   성공적으로 IP 추출된 도메인: {success_count:,}개")
        logging.info(f"   실패한 도메인: {processed_count - success_count:,}개")
        logging.info(f"   성공률: {(success_count/processed_count*100):.1f}%")
        logging.info(f"   실패률: {((processed_count-success_count)/processed_count*100):.1f}%")
        
        return True
    else:
        return False

def main():
    if len(sys.argv) != 2:
        print("사용법: python extract_ip_from_domains.py <도메인_리스트_파일>")
        print("예시: python extract_ip_from_domains.py websitelist/web_1000.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # 출력 파일명 생성
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    today = date.today().strftime("%Y%m%d")
    output_file = f"ip_extracted_{base_name}_{today}.csv"
    
    start_time = time.time()
    
    success = process_domain_file(input_file, output_file)
    
    if success:
        print(f"\n{'='*60}")
        print(f"✅ IP 추출 완료!")
        print(f" 입력 파일: {input_file}")
        print(f"📁 출력 파일: {output_file}")
        print(f"⏱️  처리 시간: {time.time() - start_time:.2f}초")
        print(f"{'='*60}")
    else:
        print("❌ 처리 중 오류가 발생했습니다.")
        sys.exit(1)

if __name__ == "__main__":
    main() 