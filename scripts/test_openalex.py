import httpx
import urllib.parse
import json

title = "KRover: A Symbolic Execution Engine for Dynamic Kernel Analysis."
url = f"https://api.openalex.org/works?filter=title.search:{urllib.parse.quote(title)}&select=title,abstract_inverted_index"

try:
    print(httpx.get(url, verify=False, timeout=10).json())
except Exception as e:
    print("Failed:", e)
