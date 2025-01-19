from pathlib import Path
import pandas as pd
import re
from collections import defaultdict

def analyze_ecn_results():
    print("Starting ECN server analysis...")
    
    # 결과 파일이 저장된 디렉토리
    result_dir = Path('./ecnserver')
    if not result_dir.exists():
        print(f"Error: Directory {result_dir} does not exist")
        return
    
    # 결과를 저장할 데이터 구조
    stats = {
        'total_servers': 0,
        'ecn_enabled': 0,
        'ecn_disabled': 0,
        'sae_only': 0,
        'errors': 0
    }
    
    domain_stats = defaultdict(lambda: {'ecn': 0, 'non_ecn': 0, 'error': 0, 'sae_only': 0})
    
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
                    domain = domain.lower()  # 도메인 정규화
                    
                    # 상태에 따른 통계 업데이트
                    if status == 'SAE-ECN':
                        stats['ecn_enabled'] += 1
                        domain_stats[domain]['ecn'] += 1
                    elif status == 'SAE-notECN':
                        stats['sae_only'] += 1
                        domain_stats[domain]['sae_only'] += 1
                    elif status == 'notSAE-notECN':
                        stats['ecn_disabled'] += 1
                        domain_stats[domain]['non_ecn'] += 1
                    elif status == 'Error':
                        stats['errors'] += 1
                        domain_stats[domain]['error'] += 1
    
    stats['total_servers'] = sum([stats['ecn_enabled'], stats['ecn_disabled'], 
                                stats['sae_only'], stats['errors']])
    
    # 결과 출력
    print("\nOverall Statistics:")
    print(f"Total servers tested: {stats['total_servers']}")
    print(f"ECN enabled servers: {stats['ecn_enabled']} ({(stats['ecn_enabled']/stats['total_servers']*100):.2f}%)")
    print(f"ECN disabled servers: {stats['ecn_disabled']} ({(stats['ecn_disabled']/stats['total_servers']*100):.2f}%)")
    print(f"SAE-only servers: {stats['sae_only']} ({(stats['sae_only']/stats['total_servers']*100):.2f}%)")
    print(f"Error responses: {stats['errors']} ({(stats['errors']/stats['total_servers']*100):.2f}%)")
    
    # 도메인별 통계를 DataFrame으로 변환
    df = pd.DataFrame.from_dict(domain_stats, orient='index')
    df['total'] = df.sum(axis=1)
    df = df.sort_values('total', ascending=False)
    
    # CSV 파일로 저장
    output_file = 'ecn_analysis_results.csv'
    df.to_csv(output_file)
    print(f"\nDetailed domain statistics saved to {output_file}")
    
    # 상위 10개 도메인 출력
    print("\nTop 10 domains by total measurements:")
    print(df.head(10))

if __name__ == "__main__":
    analyze_ecn_results()
