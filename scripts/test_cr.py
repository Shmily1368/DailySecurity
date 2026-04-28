import urllib.request
import json
doi = "10.1145/3576915.3623198"
url = f"https://api.crossref.org/works/{doi}"
req = urllib.request.Request(url, headers={'User-Agent': 'mailto:test@example.com'})
try:
    with urllib.request.urlopen(req, timeout=10) as response:
        data = json.loads(response.read().decode())
        print(data['message'].get('abstract', 'No abstract found'))
except Exception as e:
    print("Failed:", e)
