import httpx
import urllib.parse
import json

title = "KRover: A Symbolic Execution Engine for Dynamic Kernel Analysis."
url = f"https://api.semanticscholar.org/graph/v1/paper/search?query={urllib.parse.quote(title)}&limit=1&fields=title,abstract"

try:
    print(httpx.get(url, verify=False, timeout=10).json())
except Exception as e:
    print("Failed:", e)
