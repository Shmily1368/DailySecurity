"""Gate redundant runs and verify the deployed snapshot without third-party dependencies."""
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
SITE = "https://www.dailysecurity.cn"


def local_snapshot():
    data = ROOT / "data"
    if not (data / "current.json").exists():
        return None
    pointer = json.loads((data / "current.json").read_text())
    digest_path = (data / pointer["digest"]).resolve()
    if not digest_path.is_relative_to((data / "generations").resolve()):
        raise ValueError("Invalid generation path")
    if hashlib.sha256(digest_path.read_bytes()).hexdigest() != pointer["sha256"]:
        raise ValueError("Invalid snapshot checksum")
    digest = json.loads(digest_path.read_text())
    if digest["date"] != pointer["date"] or digest.get("is_mock"):
        raise ValueError("Invalid production digest")
    return pointer


def public_manifest():
    request = Request(f"{SITE}/health.json?t={time.time_ns()}", headers={"Cache-Control": "no-cache"})
    with urlopen(request, timeout=15) as response:
        return json.load(response)


def main():
    mode = sys.argv[1]
    pointer = local_snapshot()
    if mode == "validate":
        from validate_data import validate_file
        digest_path = ROOT / "data" / pointer["digest"] if pointer else ROOT / "data/daily/latest.json"
        valid, errors = validate_file(digest_path, "digest")
        if not valid:
            raise ValueError(f"Production digest failed schema validation: {errors[:5]}")
        if pointer:
            print(f"Verified snapshot {pointer['date']} ({pointer['item_count']} items)")
        else:
            digest = json.loads((ROOT / "data/daily/latest.json").read_text())
            if digest.get("is_mock"):
                raise ValueError("Mock data cannot be deployed")
            print("Verified legacy production snapshot")
        return 0
    if mode == "gate":
        today = datetime.now(ZoneInfo("Asia/Shanghai")).date().isoformat()
        already = False
        if pointer and pointer["date"] == today and os.getenv("FORCE_REFRESH") != "true":
            try:
                live = public_manifest()
                already = (live["version"] == pointer["sha256"] and live["date"] == today
                           and bool(os.getenv("DATA_COMMIT")) and live.get("commit") == os.getenv("DATA_COMMIT")
                           and not live.get("is_mock"))
            except Exception:
                pass
        healthy = pointer and pointer.get("health", {}).get("status") == "healthy"
        # A verified healthy edition skips collection; an unpublished edition only needs deployment.
        collect = not (pointer and pointer["date"] == today and healthy and os.getenv("FORCE_REFRESH") != "true")
        deploy = collect or not already
        values = {"collect": str(bool(collect)).lower(), "deploy": str(bool(deploy)).lower()}
        if os.getenv("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as out:
                for key, value in values.items():
                    out.write(f"{key}={value}\n")
        print(values)
        return 0
    if mode != "verify":
        raise ValueError("Unknown publication command")
    date = pointer["date"] if pointer else json.loads((ROOT / "data/daily/latest.json").read_text())["date"]
    for attempt in range(8):
        try:
            live = public_manifest()
            if ((pointer is None or live["version"] == pointer["sha256"]) and live["date"] == date
                    and live.get("commit") == os.getenv("DATA_COMMIT") and not live.get("is_mock")):
                print(f"Public edition verified: {live['date']}, {live['item_count']} items")
                return 0
        except Exception as exc:
            print(f"Public check {attempt + 1}: {type(exc).__name__}")
        if attempt < 7:
            time.sleep(10)
    print("::error::Public manifest did not match the deployed commit and snapshot")
    return 1


if __name__ == "__main__":
    sys.exit(main())
