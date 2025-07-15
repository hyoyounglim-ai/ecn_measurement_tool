import pandas as pd

# 원본 파일 경로
CSV_FILE = 'asn/asn_prefixes.csv'
# 샘플 파일 경로
OUTPUT_FILE = 'asn/asn_prefixes_sampled.csv'

# 데이터 읽기
df = pd.read_csv(CSV_FILE)

# 국가+업체별로 1개씩 우선 추출 (최대한 다양하게)
group_cols = ['country_code', 'description']
sampled = df.groupby(group_cols, group_keys=False).apply(lambda x: x.sample(1, random_state=42))

# 전체 10% 목표 개수
target_count = int(len(df) * 0.1)

# 부족하면 나머지는 랜덤하게 추가 추출 (이미 뽑힌 것은 제외)
if len(sampled) < target_count:
    remaining = df.drop(sampled.index)
    additional = remaining.sample(target_count - len(sampled), random_state=42)
    sampled = pd.concat([sampled, additional])

# 너무 많으면 랜덤하게 10%만 남김
elif len(sampled) > target_count:
    sampled = sampled.sample(target_count, random_state=42)

# 결과 저장
sampled.to_csv(OUTPUT_FILE, index=False)
print(f"샘플링된 IP대역 {len(sampled)}개가 {OUTPUT_FILE}에 저장되었습니다.")