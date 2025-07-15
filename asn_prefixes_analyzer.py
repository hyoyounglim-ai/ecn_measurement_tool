import csv
from collections import defaultdict, Counter

# 파일 경로
CSV_FILE = 'asn/asn_prefixes.csv'

def main():
    country_prefix_count = Counter()
    country_asn_set = defaultdict(set)
    country_description_count = defaultdict(Counter)
    description_count = Counter()
    country_name_map = {}

    with open(CSV_FILE, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            prefix = row['prefix']
            description = row['description']
            asn = row['asn']
            country_code = row['country_code']
            country_name = row['country_name']

            country_prefix_count[country_code] += 1
            country_asn_set[country_code].add(asn)
            country_description_count[country_code][description] += 1
            description_count[description] += 1
            country_name_map[country_code] = country_name

    print('국가별 IP(프리픽스) 개수:')
    for cc, count in country_prefix_count.most_common():
        print(f"{cc} ({country_name_map[cc]}): {count}")
    print('\n국가별 고유 ASN 개수:')
    for cc, asns in country_asn_set.items():
        print(f"{cc} ({country_name_map[cc]}): {len(asns)}")
    print('\n국가별 업체(Description)별 프리픽스 개수 상위 3개:')
    for cc, desc_counter in country_description_count.items():
        print(f"{cc} ({country_name_map[cc]}):")
        for desc, cnt in desc_counter.most_common(3):
            print(f"  {desc}: {cnt}")
    print('\n가장 많은 프리픽스를 가진 상위 5개 업체:')
    for desc, cnt in description_count.most_common(5):
        print(f"{desc}: {cnt}")
    print('\n가장 많은 프리픽스를 가진 상위 5개 국가:')
    for cc, cnt in country_prefix_count.most_common(5):
        print(f"{cc} ({country_name_map[cc]}): {cnt}")

    print('\n전세계 IP 분포 요약:')
    total_prefixes = sum(country_prefix_count.values())
    for cc, cnt in country_prefix_count.most_common():
        percent = cnt / total_prefixes * 100
        print(f"{cc} ({country_name_map[cc]}): {cnt} ({percent:.2f}%)")

if __name__ == '__main__':
    main() 