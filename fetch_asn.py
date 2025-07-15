import requests, csv, time


API_KEY = "bdc_a2cc491320bd4dbfbb9963083ffa9775"
## TODO : 
## https://www.bigdatacloud.com/account 에서 로그인해서 키 받기

def get_top_asns(limit=1000):
    url = "https://api-bdc.net/data/asn-rank-list"
    try:
        resp = requests.get(url, params={
            "batchSize": limit,
            "offset": 0,
            "sort": "rank",
            "order": "asc",
            "localityLanguage": "en",
            "key": API_KEY
        })
        resp.raise_for_status()
        return resp.json().get("asns", [])
    except Exception as e:
        print(f"[ERROR] get_top_asns failed: {e}")
        return []
        
def query_bgpview(asn):
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/114.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://bgpview.io/",
        "Origin": "https://bgpview.io",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    try:
        url = f"https://api.bgpview.io/asn/{asn}"
        resp = session.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        name = data.get("name", "")
        country = data.get("country_code", "")
        prefix = data.get("prefixes", {}).get("ipv4_prefixes", [{}])[0].get("prefix", "")
        return name, country, prefix
    except Exception as e:
        print(f"[!] Error for ASN {asn}: {e}")
        return "", "", ""


def query_peeringdb(asn):
    try:
        resp = requests.get(f"https://www.peeringdb.com/api/net?asn={asn}", timeout=10)
        resp.raise_for_status()
        arr = resp.json().get("data", [])
        return arr[0].get("city", "") if arr else ""
    except Exception as e:
        print(f"[!] Error in query_peeringdb for ASN {asn}: {e}")
        return ""

with open("top1000_asn_info.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["asn", "org_name", "country", "city", "prefix"])
    for i, entry in enumerate(get_top_asns(1000)):
        asn = entry.get("asnNumeric") or entry.get("asn")
        if not asn:
            continue
        org, country, prefix = query_bgpview(asn)
        city = query_peeringdb(asn)
        print(f"[{i+1}/1000] ASN {asn} - {org} ({country}) - {city} - {prefix}")
        w.writerow([asn, org, country, city, prefix])
        time.sleep(0.2)


# def get_top_asns(limit=1000):
#     url = "https://api-bdc.net/data/asn-rank-list"
#     resp = requests.get(url, params={
#         "batchSize": limit,
#         "offset": 0,
#         "sort": "rank",
#         "order": "asc",
#         "localityLanguage": "en",
#         "key": API_KEY
#     })
#     return resp.json().get("asns", [])

# def query_bgpview(asn):
#     resp = requests.get(f"https://api.bgpview.io/asn/{asn}")
#     data = resp.json().get("data", {})
#     return (
#         data.get("name", ""),
#         data.get("country_code", ""),
#         data.get("prefixes", {}).get("ipv4_prefixes", [{}])[0].get("prefix", "")
#     )

# def query_peeringdb(asn):
#     resp = requests.get(f"https://www.peeringdb.com/api/net?asn={asn}")
#     arr = resp.json().get("data", [])
#     return arr[0].get("city", "") if arr else ""

# with open("top1000_asn_info.csv", "w", newline="") as f:
#     w = csv.writer(f)
#     w.writerow(["asn","org_name","country","city","prefix"])
#     for entry in get_top_asns(1000):
#         asn = entry["asnNumeric"]
#         org, country, prefix = query_bgpview(asn)
#         city = query_peeringdb(asn)
#         w.writerow([asn, org, country, city, prefix])
#         time.sleep(0.2)
