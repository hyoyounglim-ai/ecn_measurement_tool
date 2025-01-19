from pathlib import Path
import pandas as pd
from collections import defaultdict
import socket

def get_local_ip():
    try:
        # 외부 연결을 통해 실제 IP 확인
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"Warning: Could not get local IP: {e}")
        return "unknown"

def analyze_ecn_results():
    print("Starting ECN server analysis...")
    
    # 로컬 IP 가져오기
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")
    
    result_dir = Path('./ecnserver')
    if not result_dir.exists():
        print(f"Error: Directory {result_dir} does not exist")
        return
    
    # 전체 통계
    stats = {
        'total_servers': 0,
        'ecn_enabled': 0,
        'ecn_disabled': 0,
        'sae_only': 0,
        'errors': 0
    }
    
    # 중복 체크를 위한 세트
    seen_results = set()  # (domain, ip, status) 튜플을 저장
    
    # 도메인별 통계: {domain: {ip: {ecn: 0, non_ecn: 0, error: 0, sae_only: 0}}}
    domain_stats = defaultdict(lambda: defaultdict(lambda: {'ecn': 0, 'non_ecn': 0, 'error': 0, 'sae_only': 0}))
    
    # 파일 분석
    for file in result_dir.glob('*'):
        if file.name.startswith('result_') or file.name.startswith('revise_'):
            print(f"Analyzing {file.name}...")
            
            with open(file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split(',')
                    if len(parts) != 3:
                        continue
                        
                    status, ip, domain = parts
                    domain = domain.lower()
                    
                    # 중복 체크
                    result_key = (domain, ip, status)
                    if result_key in seen_results:
                        continue
                    seen_results.add(result_key)
                    
                    # 상태에 따른 통계 업데이트
                    if status == 'SAE-ECN':
                        stats['ecn_enabled'] += 1
                        domain_stats[domain][ip]['ecn'] += 1
                    elif status == 'SAE-notECN':
                        stats['sae_only'] += 1
                        domain_stats[domain][ip]['sae_only'] += 1
                    elif status == 'notSAE-notECN':
                        stats['ecn_disabled'] += 1
                        domain_stats[domain][ip]['non_ecn'] += 1
                    elif status == 'Error':
                        stats['errors'] += 1
                        domain_stats[domain][ip]['error'] += 1
    
    print(f"\nRemoved {len(seen_results)} duplicate entries")
    
    stats['total_servers'] = sum([stats['ecn_enabled'], stats['ecn_disabled'], 
                                stats['sae_only'], stats['errors']])
    
    # 결과 출력
    print("\nOverall Statistics:")
    print(f"Total servers tested: {stats['total_servers']}")
    print(f"ECN enabled servers: {stats['ecn_enabled']} ({(stats['ecn_enabled']/stats['total_servers']*100):.2f}%)")
    print(f"ECN disabled servers: {stats['ecn_disabled']} ({(stats['ecn_disabled']/stats['total_servers']*100):.2f}%)")
    print(f"SAE-only servers: {stats['sae_only']} ({(stats['sae_only']/stats['total_servers']*100):.2f}%)")
    print(f"Error responses: {stats['errors']} ({(stats['errors']/stats['total_servers']*100):.2f}%)")
    
    # DataFrame 생성 및 저장
    rows = []
    sae_only_rows = []  # SAE-only 결과를 위한 별도 리스트
    
    for domain, ips in domain_stats.items():
        for ip, stats in ips.items():
            row = {
                'domain': domain,
                'ip': ip,
                'ecn_enabled': stats['ecn'],
                'ecn_disabled': stats['non_ecn'],
                'sae_only': stats['sae_only'],
                'errors': stats['error'],
                'total': sum(stats.values())
            }
            rows.append(row)
            
            # SAE-only 결과가 있는 경우 별도 저장
            if stats['sae_only'] > 0:
                sae_only_row = {
                    'domain': domain,
                    'ip': ip,
                    'count': stats['sae_only']
                }
                sae_only_rows.append(sae_only_row)
    
    # 전체 결과 DataFrame
    df = pd.DataFrame(rows)
    df = df.sort_values(['domain', 'total'], ascending=[True, False])
    
    # SAE-only 결과 DataFrame
    sae_df = pd.DataFrame(sae_only_rows)
    if not sae_df.empty:
        sae_df = sae_df.sort_values(['count', 'domain'], ascending=[False, True])
    
    # CSV 파일로 저장 (IP 주소 포함)
    output_file = f'ecn_analysis_results_{local_ip}.csv'
    df.to_csv(output_file, index=False)
    print(f"\nDetailed statistics saved to {output_file}")
    
    sae_output_file = f'sae_only_results_{local_ip}.csv'
    sae_df.to_csv(sae_output_file, index=False)
    print(f"SAE-only results saved to {sae_output_file}")
    
    # SAE-only 결과 출력
    if not sae_df.empty:
        print("\nServers with SAE-only responses:")
        print(sae_df.to_string(index=False))
    else:
        print("\nNo SAE-only responses found")
    
    # 도메인별 IP 수 출력
    domain_ip_counts = df.groupby('domain').size()
    print("\nDomains with multiple IPs:")
    for domain, count in domain_ip_counts[domain_ip_counts > 1].items():
        print(f"{domain}: {count} IPs")
    
    # 상위 10개 도메인의 상세 정보 출력
    print("\nTop 10 domains by total measurements:")
    top_domains = df.groupby('domain')['total'].sum().nlargest(10)
    for domain in top_domains.index:
        print(f"\n{domain}:")
        domain_data = df[df['domain'] == domain]
        print(domain_data.to_string(index=False))

if __name__ == "__main__":
    analyze_ecn_results()
