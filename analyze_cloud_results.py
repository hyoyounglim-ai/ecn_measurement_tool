#!/usr/bin/env python3
import csv
import sys
import os
import pandas as pd
import numpy as np
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import json

def load_csv_file(file_path):
    """
    CSV 파일을 로드하고 기본 정보를 반환
    """
    try:
        df = pd.read_csv(file_path)
        print(f"📁 파일 로드: {file_path}")
        print(f"   - 총 행 수: {len(df):,}개")
        print(f"   - 컬럼: {list(df.columns)}")
        
        # 디버깅: 컬럼명 확인
        print(f"   - 컬럼 타입: {df.dtypes.to_dict()}")
        
        # 디버깅: IP_Address 컬럼의 고유값 확인
        if 'IP_Address' in df.columns:
            unique_ips = df['IP_Address'].unique()
            print(f"   - IP_Address 고유값 (상위 10개): {unique_ips[:10]}")
            print(f"   - IP_Address 고유값 개수: {len(unique_ips)}")
            
            # N/A 관련 값들 확인
            na_values = df[df['IP_Address'].str.contains('N/A', na=False, case=False)]
            print(f"   - N/A 포함된 행 수: {len(na_values)}")
            
            # 정확히 'N/A'인 값들 확인
            exact_na = df[df['IP_Address'] == 'N/A']
            print(f"   - 정확히 'N/A'인 행 수: {len(exact_na)}")
            
            # 대소문자 구분 없이 'na'인 값들 확인
            na_lower = df[df['IP_Address'].str.lower() == 'n/a']
            print(f"   - 소문자 'n/a'인 행 수: {len(na_lower)}")
            
            # 공백이 포함된 'N/A' 값들 확인
            na_with_spaces = df[df['IP_Address'].str.strip() == 'N/A']
            print(f"   - 공백 제거 후 'N/A'인 행 수: {len(na_with_spaces)}")
        
        return df
    except Exception as e:
        print(f"❌ 파일 로드 실패: {file_path} - {e}")
        return None

def load_ip_regions(file_path='ip_regions.txt'):
    """
    IP 지역 분류 정의 파일을 로드
    """
    ip_regions = {}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # 주석이나 빈 줄 무시
                if not line or line.startswith('#'):
                    continue
                
                # CSV 형식으로 파싱
                parts = line.split(',', 2)  # 최대 2번만 분할
                if len(parts) >= 2:
                    ip_class = parts[0].strip()
                    region = parts[1].strip()
                    ip_regions[ip_class] = region
        
        print(f"📁 IP 지역 분류 파일 로드: {file_path}")
        print(f"   - 총 {len(ip_regions)}개 IP 클래스 정의")
        return ip_regions
        
    except FileNotFoundError:
        print(f"❌ IP 지역 분류 파일을 찾을 수 없습니다: {file_path}")
        return {}
    except Exception as e:
        print(f"❌ IP 지역 분류 파일 로드 실패: {e}")
        return {}

def normalize_ip_for_comparison(ip):
    """
    IP를 A, B, C 클래스 대역으로 정규화 (D 클래스 제거)
    """
    if ip == 'N/A':
        return 'N/A'
    
    parts = ip.split('.')
    if len(parts) >= 3:
        # A.B.C.0 형태로 정규화
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
    elif len(parts) == 2:
        # A.B.0.0 형태로 정규화
        return f"{parts[0]}.{parts[1]}.0.0"
    elif len(parts) == 1:
        # A.0.0.0 형태로 정규화
        return f"{parts[0]}.0.0.0"
    else:
        return ip

def is_blocked_ip(ip):
    """
    IP가 차단된 상태인지 확인 (다양한 N/A 형태 지원)
    """
    if pd.isna(ip):  # NaN 값
        return True
    
    if isinstance(ip, str):
        ip_clean = ip.strip().lower()
        blocked_values = ['n/a', 'na', 'none', 'null', 'error', 'timeout', 'blocked']
        return ip_clean in blocked_values
    
    return False

def analyze_single_file(df, file_name):
    """
    단일 파일 분석
    """
    print(f"\n{'='*50}")
    print(f"📊 {file_name} 분석 결과")
    print(f"{'='*50}")
    
    # 디버깅: IP_Address 컬럼 확인
    if 'IP_Address' not in df.columns:
        print(f"❌ IP_Address 컬럼이 없습니다. 사용 가능한 컬럼: {list(df.columns)}")
        return None
    
    # 기본 통계 (다양한 N/A 형태 지원)
    total_domains = len(df)
    
    # 차단된 도메인 확인 (다양한 방법으로)
    blocked_methods = {
        'exact_na': len(df[df['IP_Address'] == 'N/A']),
        'na_lower': len(df[df['IP_Address'].str.lower() == 'n/a']),
        'na_strip': len(df[df['IP_Address'].str.strip() == 'N/A']),
        'na_contains': len(df[df['IP_Address'].str.contains('N/A', na=False, case=False)]),
        'is_blocked_func': len(df[df['IP_Address'].apply(is_blocked_ip)])
    }
    
    print(f"🔍 차단 도메인 분석 (다양한 방법):")
    for method, count in blocked_methods.items():
        print(f"   {method}: {count:,}개")
    
    # 가장 많은 차단 도메인을 찾는 방법 사용
    blocked_domains = max(blocked_methods.values())
    valid_ips = total_domains - blocked_domains
    
    print(f"\n 기본 통계:")
    print(f"   총 도메인 수: {total_domains:,}개")
    print(f"   접근 가능한 도메인: {valid_ips:,}개")
    print(f"   차단된 도메인: {blocked_domains:,}개")
    print(f"   접근 성공률: {(valid_ips/total_domains*100):.2f}%")
    print(f"   차단 비율: {(blocked_domains/total_domains*100):.2f}%")
    
    # 디버깅: 차단된 도메인 샘플 확인
    if blocked_domains > 0:
        blocked_sample = df[df['IP_Address'].apply(is_blocked_ip)].head(5)
        print(f"\n🔍 차단된 도메인 샘플 (상위 5개):")
        for idx, row in blocked_sample.iterrows():
            print(f"   {row['Domain']} -> {row['IP_Address']}")
    
    # IP 클래스 분석
    if valid_ips > 0:
        valid_df = df[~df['IP_Address'].apply(is_blocked_ip)]
        
        # A 클래스 분석
        a_classes = valid_df['IP_Address'].str.split('.').str[0].value_counts()
        print(f"\n A 클래스 분포 (상위 10개):")
        for i, (a_class, count) in enumerate(a_classes.head(10).items(), 1):
            percentage = (count / valid_ips) * 100
            print(f"   {i:2d}. {a_class}.0.0.0/8: {count:,}개 ({percentage:.2f}%)")
        
        # B 클래스 분석
        b_classes = valid_df['IP_Address'].str.split('.').str[:2].str.join('.').value_counts()
        print(f"\n B 클래스 분포 (상위 10개):")
        for i, (b_class, count) in enumerate(b_classes.head(10).items(), 1):
            percentage = (count / valid_ips) * 100
            print(f"   {i:2d}. {b_class}.0.0/16: {count:,}개 ({percentage:.2f}%)")
    
    return {
        'file_name': file_name,
        'total_domains': total_domains,
        'valid_ips': valid_ips,
        'blocked_domains': blocked_domains,
        'success_rate': valid_ips/total_domains*100,
        'blocked_rate': blocked_domains/total_domains*100,
        'blocked_methods': blocked_methods
    }

def compare_cloud_results(results_list):
    """
    클라우드 간 결과 비교 (2개 이상 파일인 경우)
    """
    if len(results_list) < 2:
        return None
    
    print(f"\n{'='*60}")
    print(f"☁️  클라우드 간 결과 비교")
    print(f"{'='*60}")
    
    # 비교 테이블 생성
    comparison_df = pd.DataFrame(results_list)
    
    print(f"📊 성공률 비교:")
    for _, row in comparison_df.iterrows():
        print(f"   {row['file_name']}: {row['success_rate']:.2f}% ({row['valid_ips']:,}/{row['total_domains']:,})")
    
    print(f"\n📊 차단 비율 비교:")
    for _, row in comparison_df.iterrows():
        print(f"   {row['file_name']}: {row['blocked_rate']:.2f}% ({row['blocked_domains']:,}/{row['total_domains']:,})")
    
    # 평균 성공률
    avg_success_rate = comparison_df['success_rate'].mean()
    print(f"\n📈 평균 성공률: {avg_success_rate:.2f}%")
    
    # 평균 차단 비율
    avg_blocked_rate = comparison_df['blocked_rate'].mean()
    print(f"📈 평균 차단 비율: {avg_blocked_rate:.2f}%")
    
    # 성공률 차이 분석
    success_rate_std = comparison_df['success_rate'].std()
    print(f" 성공률 표준편차: {success_rate_std:.2f}%")
    
    if success_rate_std > 5:
        print(f"⚠️  성공률 차이가 큽니다 (표준편차 > 5%)")
    else:
        print(f"✅ 성공률이 일관적입니다")
    
    return comparison_df

def analyze_domain_ip_differences(df_list, file_names):
    """
    같은 도메인인데 IP가 다른 경우 분석 (2개 이상 파일인 경우)
    """
    if len(df_list) < 2:
        return None
    
    print(f"\n{'='*60}")
    print(f"🔄 도메인별 IP 차이 분석")
    print(f"{'='*60}")
    
    # 모든 도메인 수집
    print("📊 도메인 수집 중...")
    all_domains = set()
    for df in df_list:
        all_domains.update(df['Domain'].tolist())
    
    print(f" 전체 고유 도메인 수: {len(all_domains):,}개")
    
    # 도메인별 IP 매핑 생성
    print("📊 도메인별 IP 매핑 생성 중...")
    domain_ip_mapping = {}
    domain_count = len(all_domains)
    
    for i, domain in enumerate(all_domains, 1):
        if i % 1000 == 0 or i == domain_count:  # 1000개마다 또는 마지막에 진행상황 출력
            progress = (i / domain_count) * 100
            print(f"   진행상황: {i:,}/{domain_count:,} ({progress:.1f}%)")
        
        domain_ip_mapping[domain] = {}
        for df, file_name in zip(df_list, file_names):
            domain_data = df[df['Domain'] == domain]
            if len(domain_data) > 0:
                domain_ip_mapping[domain][file_name] = domain_data.iloc[0]['IP_Address']
            else:
                domain_ip_mapping[domain][file_name] = 'NOT_FOUND'
    
    # IP 차이 분석
    print("📊 IP 차이 분석 중...")
    same_ip_count = 0
    different_ip_count = 0
    blocked_differences = 0
    ip_differences = []
    
    for i, (domain, ip_dict) in enumerate(domain_ip_mapping.items(), 1):
        if i % 1000 == 0 or i == domain_count:  # 1000개마다 또는 마지막에 진행상황 출력
            progress = (i / domain_count) * 100
            print(f"   진행상황: {i:,}/{domain_count:,} ({progress:.1f}%) - 동일: {same_ip_count:,}, 다름: {different_ip_count:,}, 차단: {blocked_differences:,}")
        
        unique_ips = set(ip_dict.values())
        unique_ips.discard('NOT_FOUND')  # NOT_FOUND는 제외
        
        # 차단된 IP들 제거
        non_blocked_ips = {ip for ip in unique_ips if not is_blocked_ip(ip)}
        
        if len(non_blocked_ips) == 0:
            # 모든 파일에서 차단됨
            blocked_differences += 1
        elif len(non_blocked_ips) == 1:
            # 모든 파일에서 같은 IP
            same_ip_count += 1
        else:
            # IP가 다름
            different_ip_count += 1
            ip_differences.append({
                'domain': domain,
                'ips': ip_dict
            })
    
    print(f"\n 도메인별 IP 일치성 분석:")
    print(f"   IP가 동일한 도메인: {same_ip_count:,}개 ({(same_ip_count/len(all_domains)*100):.2f}%)")
    print(f"   IP가 다른 도메인: {different_ip_count:,}개 ({(different_ip_count/len(all_domains)*100):.2f}%)")
    print(f"   모든 파일에서 차단된 도메인: {blocked_differences:,}개 ({(blocked_differences/len(all_domains)*100):.2f}%)")
    
    # IP가 다른 도메인들의 상세 분석
    if ip_differences:
        print(f"\n📊 IP가 다른 도메인 상위 10개:")
        for i, diff in enumerate(ip_differences[:10], 1):
            print(f"   {i:2d}. {diff['domain']}")
            for file_name, ip in diff['ips'].items():
                status = "차단됨" if is_blocked_ip(ip) else f"IP: {ip}"
                print(f"       {file_name}: {status}")
    
    return {
        'total_domains': len(all_domains),
        'same_ip_count': same_ip_count,
        'different_ip_count': different_ip_count,
        'blocked_differences': blocked_differences,
        'ip_differences': ip_differences
    }

def analyze_ip_overlap(df_list, file_names):
    """
    IP 중복 분석 (A, B, C 클래스 대역 기준) - 2개 이상 파일인 경우
    """
    if len(df_list) < 2:
        return None
    
    print(f"\n{'='*60}")
    print(f"🔄 IP 중복 분석 (A, B, C 클래스 대역 기준)")
    print(f"{'='*60}")
    
    # 각 파일의 유효한 IP 집합 생성 (정규화된 IP 사용)
    ip_sets = {}
    normalized_ip_counts = defaultdict(int)
    
    for df, file_name in zip(df_list, file_names):
        valid_df = df[~df['IP_Address'].apply(is_blocked_ip)]
        normalized_ips = set()
        
        for ip in valid_df['IP_Address']:
            normalized_ip = normalize_ip_for_comparison(ip)
            if normalized_ip != 'N/A':
                normalized_ips.add(normalized_ip)
                normalized_ip_counts[normalized_ip] += 1
        
        ip_sets[file_name] = normalized_ips
        print(f" {file_name}: {len(normalized_ips):,}개 유효 IP (정규화 후)")
    
    # 모든 IP의 합집합과 교집합 계산
    all_ips = set.union(*ip_sets.values())
    common_ips = set.intersection(*ip_sets.values())
    
    print(f"\n 중복 분석:")
    print(f"   전체 고유 IP 수 (정규화): {len(all_ips):,}개")
    print(f"   모든 클라우드에서 공통 IP: {len(common_ips):,}개")
    print(f"   공통 IP 비율: {(len(common_ips)/len(all_ips)*100):.2f}%")
    
    # 쌍별 중복 분석
    print(f"\n📊 쌍별 중복 분석:")
    for i, file1 in enumerate(file_names):
        for j, file2 in enumerate(file_names[i+1:], i+1):
            intersection = len(ip_sets[file1] & ip_sets[file2])
            union = len(ip_sets[file1] | ip_sets[file2])
            jaccard = intersection / union if union > 0 else 0
            print(f"   {file1} ↔ {file2}: {intersection:,}개 중복 (Jaccard: {jaccard:.3f})")
    
    # 중복 개수별 분포
    print(f"\n📈 중복 개수별 분포:")
    count_distribution = Counter(normalized_ip_counts.values())
    for count, frequency in sorted(count_distribution.items()):
        print(f"   {count}개 클라우드에서 발견: {frequency:,}개 IP")
    
    return {
        'all_ips': all_ips,
        'common_ips': common_ips,
        'ip_sets': ip_sets,
        'normalized_ip_counts': normalized_ip_counts
    }

def generate_deduplicated_ip_list(overlap_data, output_file):
    """
    중복을 제거한 IP 리스트와 중복 개수를 포함한 결과 파일 생성
    """
    if not overlap_data:
        return
    
    print(f"\n{'='*60}")
    print(f"📋 중복 제거 IP 리스트 생성")
    print(f"{'='*60}")
    
    # 중복 개수별로 정렬된 IP 리스트 생성
    sorted_ips = sorted(overlap_data['normalized_ip_counts'].items(), 
                       key=lambda x: (x[1], x[0]), reverse=True)
    
    # CSV 파일로 저장
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['IP_Address', 'Occurrence_Count', 'Network_Class'])
        
        for ip, count in sorted_ips:
            # 네트워크 클래스 판단
            parts = ip.split('.')
            if len(parts) >= 3 and parts[3] == '0':
                if parts[2] == '0':
                    if parts[1] == '0':
                        network_class = f"A Class ({parts[0]}.0.0.0/8)"
                    else:
                        network_class = f"B Class ({parts[0]}.{parts[1]}.0.0/16)"
                else:
                    network_class = f"C Class ({parts[0]}.{parts[1]}.{parts[2]}.0/24)"
            else:
                network_class = "Other"
            
            writer.writerow([ip, count, network_class])
    
    print(f" 중복 제거 IP 리스트가 {output_file}에 저장되었습니다.")
    print(f"   - 총 {len(sorted_ips):,}개 고유 IP")
    print(f"   - 최대 중복 횟수: {max(overlap_data['normalized_ip_counts'].values())}회")
    print(f"   - 최소 중복 횟수: {min(overlap_data['normalized_ip_counts'].values())}회")

def analyze_geographic_distribution(df_list, file_names, ip_regions):
    """
    지리적 분포 분석 (IP 클래스 기반)
    """
    print(f"\n{'='*60}")
    print(f"🌍 지리적 분포 분석 (IP 클래스 기반)")
    print(f"{'='*60}")
    
    if not ip_regions:
        print("⚠️  IP 지역 분류 정보가 없어 지리적 분포 분석을 건너뜁니다.")
        return
    
    for i, (df, file_name) in enumerate(zip(df_list, file_names)):
        valid_df = df[~df['IP_Address'].apply(is_blocked_ip)]
        if len(valid_df) == 0:
            continue
            
        print(f"\n {file_name} 지리적 분포:")
        
        # IP 클래스별 분포 (B 클래스 우선, A 클래스 차선)
        region_counts = defaultdict(int)
        for ip in valid_df['IP_Address']:
            ip_parts = ip.split('.')
            
            # B 클래스 먼저 확인 (예: 10.0., 172.16. 등)
            if len(ip_parts) >= 2:
                b_class = f"{ip_parts[0]}.{ip_parts[1]}."
                if b_class in ip_regions:
                    region = ip_regions[b_class]
                    region_counts[region] += 1
                    continue
            
            # A 클래스 확인 (예: 1., 2. 등)
            a_class = f"{ip_parts[0]}."
            if a_class in ip_regions:
                region = ip_regions[a_class]
                region_counts[region] += 1
            else:
                region_counts['기타'] += 1
        
        # 상위 10개 지역 출력
        sorted_regions = sorted(region_counts.items(), key=lambda x: x[1], reverse=True)
        for j, (region, count) in enumerate(sorted_regions[:10], 1):
            percentage = (count / len(valid_df)) * 100
            print(f"   {j:2d}. {region}: {count:,}개 ({percentage:.2f}%)")

def generate_summary_report(results_list, overlap_data, domain_diff_data, output_file):
    """
    요약 보고서 생성
    """
    print(f"\n{'='*60}")
    print(f"📋 요약 보고서 생성")
    print(f"{'='*60}")
    
    report = {
        'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_files': len(results_list),
        'files': results_list,
        'summary_stats': {
            'avg_success_rate': np.mean([r['success_rate'] for r in results_list]),
            'min_success_rate': min([r['success_rate'] for r in results_list]),
            'max_success_rate': max([r['success_rate'] for r in results_list]),
            'avg_blocked_rate': np.mean([r['blocked_rate'] for r in results_list]),
            'total_domains': sum([r['total_domains'] for r in results_list]),
            'total_valid_ips': sum([r['valid_ips'] for r in results_list]),
            'total_blocked_domains': sum([r['blocked_domains'] for r in results_list])
        }
    }
    
    # 2개 이상 파일인 경우 추가 정보
    if len(results_list) >= 2:
        if overlap_data:
            report['overlap_analysis'] = {
                'total_unique_ips': len(overlap_data['all_ips']),
                'common_ips': len(overlap_data['common_ips']),
                'common_ip_ratio': len(overlap_data['common_ips']) / len(overlap_data['all_ips']) * 100 if len(overlap_data['all_ips']) > 0 else 0,
                'max_occurrence': max(overlap_data['normalized_ip_counts'].values()) if overlap_data['normalized_ip_counts'] else 0,
                'min_occurrence': min(overlap_data['normalized_ip_counts'].values()) if overlap_data['normalized_ip_counts'] else 0
            }
        
        if domain_diff_data:
            report['domain_difference_analysis'] = {
                'total_domains': domain_diff_data['total_domains'],
                'same_ip_count': domain_diff_data['same_ip_count'],
                'different_ip_count': domain_diff_data['different_ip_count'],
                'blocked_differences': domain_diff_data['blocked_differences'],
                'same_ip_ratio': domain_diff_data['same_ip_count'] / domain_diff_data['total_domains'] * 100,
                'different_ip_ratio': domain_diff_data['different_ip_count'] / domain_diff_data['total_domains'] * 100
            }
    
    # JSON 파일로 저장
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f" 보고서가 {output_file}에 저장되었습니다.")
    
    # 요약 출력
    print(f"\n 전체 요약:")
    print(f"   분석 파일 수: {report['total_files']}개")
    print(f"   총 도메인 수: {report['summary_stats']['total_domains']:,}개")
    print(f"   총 유효 IP 수: {report['summary_stats']['total_valid_ips']:,}개")
    print(f"   총 차단된 도메인 수: {report['summary_stats']['total_blocked_domains']:,}개")
    print(f"   평균 성공률: {report['summary_stats']['avg_success_rate']:.2f}%")
    print(f"   평균 차단 비율: {report['summary_stats']['avg_blocked_rate']:.2f}%")
    
    if len(results_list) >= 2 and 'overlap_analysis' in report:
        print(f"   전체 고유 IP 수 (정규화): {report['overlap_analysis']['total_unique_ips']:,}개")
        print(f"   공통 IP 비율: {report['overlap_analysis']['common_ip_ratio']:.2f}%")
    
    if len(results_list) >= 2 and 'domain_difference_analysis' in report:
        print(f"   IP가 동일한 도메인 비율: {report['domain_difference_analysis']['same_ip_ratio']:.2f}%")
        print(f"   IP가 다른 도메인 비율: {report['domain_difference_analysis']['different_ip_ratio']:.2f}%")

def main():
    if len(sys.argv) < 2:
        print("사용법: python analyze_cloud_results.py <CSV_파일1> [CSV_파일2] [CSV_파일3] ...")
        print("예시: python analyze_cloud_results.py cloud1_results.csv")
        print("예시: python analyze_cloud_results.py cloud1_results.csv cloud2_results.csv cloud3_results.csv")
        sys.exit(1)
    
    # 파일 목록
    csv_files = sys.argv[1:]
    
    print(f"🔍 {len(csv_files)}개 클라우드 결과 분석 시작")
    print(f"📁 분석할 파일들: {csv_files}")
    
    # IP 지역 분류 파일 로드
    ip_regions = load_ip_regions()
    
    # 파일 로드
    df_list = []
    file_names = []
    results_list = []
    
    for csv_file in csv_files:
        df = load_csv_file(csv_file)
        if df is not None:
            df_list.append(df)
            file_name = os.path.basename(csv_file)
            file_names.append(file_name)
            
            # 단일 파일 분석
            result = analyze_single_file(df, file_name)
            if result:
                results_list.append(result)
    
    if len(df_list) == 0:
        print("분석 가능한 파일이 없습니다.")
        sys.exit(1)
    
    # 클라우드 간 비교 (2개 이상 파일인 경우)
    comparison_df = compare_cloud_results(results_list)
    
    # 도메인별 IP 차이 분석 (2개 이상 파일인 경우)
    domain_diff_data = analyze_domain_ip_differences(df_list, file_names)
    
    # IP 중복 분석 (2개 이상 파일인 경우)
    overlap_data = analyze_ip_overlap(df_list, file_names)
    
    # 지리적 분포 분석
    analyze_geographic_distribution(df_list, file_names, ip_regions)
    
    # 중복 제거 IP 리스트 생성 (2개 이상 파일인 경우)
    dedup_file = None
    if overlap_data:
        dedup_file = f"deduplicated_ip_list_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        generate_deduplicated_ip_list(overlap_data, dedup_file)
    
    # 요약 보고서 생성
    report_file = f"cloud_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    generate_summary_report(results_list, overlap_data, domain_diff_data, report_file)
    
    print(f"\n{'='*60}")
    print(f"✅ 분석 완료!")
    print(f"📄 상세 보고서: {report_file}")
    if dedup_file:
        print(f"📄 중복 제거 IP 리스트: {dedup_file}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main() 