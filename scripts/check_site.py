"""Integration acceptance for the actual static output, not just a successful build exit."""
import json
import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
dist = ROOT / "src/dist"
files = [p for p in dist.rglob("*") if p.is_file()]
html = [p for p in files if p.suffix == ".html"]
total = sum(p.stat().st_size for p in files)
assert total < 950_000_000, f"Pages artifact too large: {total}"
assert max(p.stat().st_size for p in html) < 1_000_000, "Unbounded HTML page"
assert (dist / "health.json").exists()
manifest = json.loads((dist / "health.json").read_text())
assert not manifest["is_mock"], "Mock data in production output"
for kind in ("catalog", "search"):
    assert (dist / manifest[kind].lstrip("/")).exists(), f"Missing {kind}"
home = (dist / "index.html").read_text()
assert len(re.findall(r'data-item-id=', home)) <= 10, "Home renders the full edition"
for p in html:
    if p.relative_to(dist).parts[0] in {"daily", "topics"} and p.name == "index.html":
        text = p.read_text()
        assert len(re.findall(r'data-item-id=', text)) <= 20, f"Pagination failure: {p}"
        for href in re.findall(r'data-detail="([^"]+)"', text):
            assert (dist / unquote(href).lstrip("/")).is_file(), f"Missing payload: {href}"
paths = [str(p.relative_to(dist)) for p in files]
assert len(paths) == len(set(paths)), "Duplicate output path"
report = {"file_count": len(files), "html_pages": len(html), "total_bytes": total,
          "largest_html_bytes": max(p.stat().st_size for p in html), "home_bytes": (dist / "index.html").stat().st_size,
          "manifest": manifest}
print(json.dumps(report, ensure_ascii=False, indent=2))
