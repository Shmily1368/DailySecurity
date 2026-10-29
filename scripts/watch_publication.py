"""Independent publication check; --recover dispatches the existing daily workflow if needed."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

from publication import ROOT, public_manifest

API = "https://api.github.com/repos/Shmily1368/DailySecurity"
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}


def github(endpoint, *, body=None, token=None):
    if token is None and body is None:
        try:
            token = credential()
        except RuntimeError:
            pass  # Public checks also work without a local authenticated checkout.
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(API + endpoint, headers=headers,
                      data=json.dumps(body).encode() if body is not None else None,
                      method="POST" if body is not None else "GET")
    with urlopen(request, timeout=20) as response:
        data = response.read()
        return json.loads(data) if data else {"accepted": True}


def credential():
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return token
    wrapper = ROOT / "git-personal"
    if not wrapper.is_file():
        raise RuntimeError("Repository-local Git authentication is unavailable")
    result = subprocess.run(
        [str(wrapper), "-c", "core.askPass=/usr/bin/false", "-c", "credential.interactive=false", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n", capture_output=True, text=True, timeout=10)
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if result.returncode or not fields.get("password"):
        raise RuntimeError("GitHub dispatch authentication is unavailable")
    return fields["password"]


def check(*, recover=False):
    today = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
    head = github("/commits/main")["sha"]
    try:
        live = public_manifest()
    except Exception:
        live = {}
    if live.get("date") == today and live.get("commit") == head and not live.get("is_mock"):
        return {"status": "current", "date": today, "commit": head, "item_count": live.get("item_count")}
    for workflow in ("daily.yml", "deploy.yml"):
        runs = github(f"/actions/workflows/{workflow}/runs?per_page=5")["workflow_runs"]
        if any(run["status"] in ACTIVE for run in runs):
            return {"status": "updating", "date": live.get("date"), "expected_date": today}
    result = {"status": "needs_recovery", "date": live.get("date"), "expected_date": today}
    if recover:
        github("/actions/workflows/daily.yml/dispatches",
               body={"ref": "main", "inputs": {"force_refresh": False}}, token=credential())
        result["status"] = "recovery_requested"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    try:
        result = check(recover=args.recover)
        print(json.dumps(result, ensure_ascii=False))
        return 1 if result["status"] == "needs_recovery" else 0
    except Exception as exc:
        # Never render credential helper output, API error bodies, or authorization values.
        print(json.dumps({"status": "check_failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
