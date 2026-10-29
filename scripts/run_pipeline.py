"""Run each source independently against fresh files, then publish a validated digest."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from validate_data import validate_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_command(name: str, args: list[str], reports: Path, statuses: list[dict],
                *, timeout: int, env: dict[str, str]) -> bool:
    print(f"[INFO] Running {name}", flush=True)
    with (reports / f"{name}.log").open("w", encoding="utf-8") as log:
        try:
            result = subprocess.run(
                [sys.executable, *args], cwd=PROJECT_ROOT, env=env,
                stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
            )
            status = {"name": name, "status": "success" if result.returncode == 0 else "failed",
                      "returncode": result.returncode}
        except subprocess.TimeoutExpired:
            status = {"name": name, "status": "timeout", "timeout_seconds": timeout}
    statuses.append(status)
    ok = status["status"] == "success"
    if not ok:
        print(f"::warning::{name}: {status['status']}; see pipeline diagnostics")
    return ok


def run_pipeline(work: Path, reports: Path, statuses: list[dict], *, mock: bool,
                 source_timeout: int, llm_timeout: int) -> bool:
    raw, processed, daily = (work / name for name in ("raw", "processed", "daily"))
    for directory in (raw, processed, daily):
        directory.mkdir()
    env = os.environ.copy()
    # 环境中遗留的 LLM_MOCK 不改变显式的运行模式。
    env["LLM_MOCK"] = "1" if mock else "0"
    state = work / "dblp_state.json"
    saved_state = PROJECT_ROOT / "data/state/dblp_state.json"
    if saved_state.exists():
        shutil.copy2(saved_state, state)
    conference_success = False

    sources = [
        ("arxiv", "fetch_arxiv.py", "arxiv_latest.json", ["--max-results", "100"]),
        ("conferences", "fetch_top_conferences.py", "top_conferences.json",
         ["--limit-per-conf", "5", "--state-file", str(state)]),
        ("kev", "fetch_cisa_kev.py", "cisa_kev.json", ["--days", "1"]),
        ("nvd", "fetch_nvd.py", "nvd_recent.json", ["--days", "1"]),
        ("epss", "fetch_epss.py", "epss_scores.json",
         ["--input", str(raw / "cisa_kev.json"), "--input", str(raw / "nvd_recent.json")]),
        ("ghsa", "fetch_github_advisory.py", "github_advisory_latest.json", []),
        ("osv", "fetch_osv.py", "osv_latest.json",
         ["--nvd-source", str(raw / "nvd_recent.json"), "--limit", "500"]),
        ("vendor", "fetch_vendor_advisories.py", "vendor_advisories.json",
         ["--days", "1", "--limit-per-source", "50"]),
        ("threat", "fetch_threat_intel.py", "threat_intel.json",
         ["--days", "1", "--limit-per-source", "50"]),
    ]
    for name, script, filename, options in sources:
        output = raw / filename
        ok = run_command(f"fetch-{name}", [f"scripts/{script}", *options, "--output", str(output)],
                         reports, statuses, timeout=source_timeout, env=env)
        if ok:
            ok, errors = validate_file(output, "raw_item")
            if not ok:
                statuses.append({"name": f"validate-{name}", "status": "failed", "errors": errors[:20]})
                print(f"::warning::{name} returned invalid business data")
        if not ok:
            # 即使脚本在异常前写了半份文件，也不能继续消费。
            output.write_text('{"items": []}\n', encoding="utf-8")
        if name == "conferences":
            conference_success = ok
        diagnostic = output.with_name(f"{output.stem}_errors.json")
        if diagnostic.exists():
            shutil.copy2(diagnostic, reports / diagnostic.name)

    groups = [
        ("paper_digest.json", ["arxiv_latest.json", "top_conferences.json"], None),
        ("daily_digest.json", ["cisa_kev.json", "nvd_recent.json",
                               "github_advisory_latest.json", "osv_latest.json"], 20),
        ("vendor_advisories_digest.json", ["vendor_advisories.json"], 30),
        ("threat_intel_digest.json", ["threat_intel.json"], 30),
    ]
    if mock or env.get("OPENAI_API_KEY"):
        for filename, inputs, limit in groups:
            output = processed / filename
            options = [part for source in inputs for part in ("--input", str(raw / source))]
            if limit is not None:
                options.extend(["--limit", str(limit)])
            if mock:
                options.append("--mock")
            ok = run_command(f"summarize-{output.stem}",
                             ["scripts/summarize_with_llm.py", *options, "--output", str(output)],
                             reports, statuses, timeout=llm_timeout, env=env)
            if ok:
                ok, errors = validate_file(output, "digest")
                if not ok:
                    statuses.append({"name": f"validate-{output.stem}", "status": "failed",
                                     "errors": errors[:20]})
            if not ok:
                output.unlink(missing_ok=True)
    else:
        print("::warning::No OPENAI_API_KEY; publishing labeled source excerpts from current raw data")
        statuses.append({"name": "summarize", "status": "source_excerpts"})

    # 保留历史日期索引，构建和校验完成前不覆盖已发布文件。
    saved_index = PROJECT_ROOT / "data/daily/index.json"
    if saved_index.exists():
        shutil.copy2(saved_index, daily / "index.json")
    if not run_command("build-digest", [
        "scripts/build_daily_digest.py", "--raw-dir", str(raw),
        "--processed-dir", str(processed), "--output-dir", str(daily),
    ], reports, statuses, timeout=llm_timeout, env=env):
        return False
    latest = daily / "latest.json"
    ok, errors = validate_file(latest, "digest")
    if not ok:
        statuses.append({"name": "validate-digest", "status": "failed", "errors": errors[:20]})
        return False
    # 日报通过两套业务校验后，才发布本次快照。
    for staged, destination in ((raw, PROJECT_ROOT / "data/raw"),
                                (processed, PROJECT_ROOT / "data/processed"),
                                (daily, PROJECT_ROOT / "data/daily")):
        destination.mkdir(parents=True, exist_ok=True)
        if staged == processed:
            for filename, _, _ in groups:
                (destination / filename).unlink(missing_ok=True)
        for path in staged.glob("*.json"):
            if path.name.endswith("_errors.json"):
                shutil.copy2(path, reports / path.name)
            else:
                shutil.copy2(path, destination / path.name)
    if conference_success and state.exists():
        saved_state.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(state, saved_state)
    statuses.append({"name": "publish", "status": "success"})
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock", action="store_true", help="Explicit development/mock mode")
    parser.add_argument("--source-timeout", type=int, default=600)
    parser.add_argument("--llm-timeout", type=int, default=600)
    parser.add_argument("--reports-dir", type=Path, default=PROJECT_ROOT / "data/tmp/pipeline")
    args = parser.parse_args()
    if args.source_timeout <= 0 or args.llm_timeout <= 0:
        parser.error("Timeouts must be positive")
    reports = args.reports_dir.resolve()
    reports.mkdir(parents=True, exist_ok=True)
    statuses: list[dict] = []
    success = False
    try:
        with tempfile.TemporaryDirectory(prefix="daily-security-") as directory:
            success = run_pipeline(Path(directory), reports, statuses, mock=args.mock,
                                   source_timeout=args.source_timeout, llm_timeout=args.llm_timeout)
    finally:
        report = {"generated_at": datetime.now(timezone.utc).isoformat(),
                  "success": success, "steps": statuses}
        (reports / "status.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as summary:
                summary.write("### Daily pipeline\n\n| Step | Status |\n| --- | --- |\n")
                for step in statuses:
                    summary.write(f"| {step['name']} | {step['status']} |\n")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
