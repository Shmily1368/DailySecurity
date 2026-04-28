import urllib.request
import urllib.parse
import json

title = "KRover: A Symbolic Execution Engine for Dynamic Kernel Analysis."
url = f"https://api.semanticscholar.org/graph/v1/paper/search?query={urllib.parse.quote(title)}&limit=1&fields=title,abstract"

try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=10) as response:
        data = json.loads(response.read().decode())
        print(data['data'][0].get('abstract', 'No abstract found'))
except Exception as e:
    print("Failed:", e)
