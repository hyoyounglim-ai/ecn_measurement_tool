import pandas as pd

# CSV 파일 경로
CSV_FILE = 'asn/asn_prefixes.csv'
OUTPUT_FILE = 'sampled_ip_list.csv'

# 데이터 읽기
df = pd.read_csv(CSV_FILE)

# 국가+업체별 그룹핑
group_cols = ['country_code', 'country_name', 'org_name']  # org_name이 업체명

# 전체 IP 개수
total_ips = len(df)
target_count = int(total_ips * 0.1)

# 각 그룹별 비율 계산
grouped = df.groupby(group_cols)
group_sizes = grouped.size().reset_index(name='count')
group_sizes['ratio'] = group_sizes['count'] / total_ips

# 각 그룹별 샘플 개수 계산 (최소 1개 보장)
group_sizes['sample_n'] = (group_sizes['ratio'] * target_count).round().astype(int)
group_sizes['sample_n'] = group_sizes['sample_n'].clip(lower=1)

# 샘플링
sampled_rows = []
for _, row in group_sizes.iterrows():
    group = df[
        (df['country_code'] == row['country_code']) &
        (df['country_name'] == row['country_name']) &
        (df['org_name'] == row['org_name'])
    ]
    n = min(row['sample_n'], len(group))
    sampled = group.sample(n=n, random_state=42)
    sampled_rows.append(sampled)

sampled_df = pd.concat(sampled_rows)

# 결과 저장
sampled_df.to_csv(OUTPUT_FILE, index=False)
print(f"샘플링된 IP 개수: {len(sampled_df)} (목표: {target_count})")
print(f"샘플링 결과가 {OUTPUT_FILE}에 저장되었습니다.")