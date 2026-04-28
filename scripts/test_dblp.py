import httpx
import json

url = "https://dblp.org/search/publ/api?q=stream:conf/ccs:2023&format=json&h=2"
try:
    res = httpx.get(url, timeout=10)
    data = res.json()
    for h in data['result']['hits']['hit']:
        print(json.dumps(h['info'], indent=2))
except Exception as e:
    print("Failed:", e)
