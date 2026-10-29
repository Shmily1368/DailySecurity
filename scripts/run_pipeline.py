"""Collect bounded independent sources and atomically publish a validated generation."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

import storage
from validate_data import validate_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACTIVE_PROCESSES = set()
KILLED_PROCESSES = set()
PROCESS_LOCK = threading.Lock()
CANCELLED = threading.Event()


@contextmanager
def process_guard():
    # A main-thread SIGTERM must not re-enter cancellation while it owns the lock.
    blocked = threading.current_thread() is threading.main_thread() and hasattr(signal, "pthread_sigmask")
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM}) if blocked else None
    try:
        with PROCESS_LOCK:
            yield
    finally:
        if blocked:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def kill_process_locked(process):
    if process in KILLED_PROCESSES:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    KILLED_PROCESSES.add(process)


def cancel_processes():
    with process_guard():
        CANCELLED.set()
        for process in tuple(ACTIVE_PROCESSES):
            kill_process_locked(process)


def terminate_pipeline(*_):
    cancel_processes()
    raise SystemExit(143)


def run_command(name, args, reports, statuses, *, timeout, env):
    print(f"[INFO] Running {name}", flush=True)
    started = time.monotonic()
    with (reports / f"{name}.log").open("w", encoding="utf-8") as log:
        process = None
        try:
            with process_guard():
                if CANCELLED.is_set():
                    raise SystemExit(143)
                process = subprocess.Popen(
                    [sys.executable, *args], cwd=PROJECT_ROOT, env=env,
                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                )
                ACTIVE_PROCESSES.add(process)
            code = process.wait(timeout=timeout)
            status = {"name": name, "status": "success" if code == 0 else "failed", "returncode": code}
        except BaseException as exc:
            if process is not None:
                with process_guard():
                    kill_process_locked(process)
                process.wait()
            if not isinstance(exc, subprocess.TimeoutExpired):
                raise
            status = {"name": name, "status": "timeout", "timeout_seconds": timeout}
        finally:
            with process_guard():
                ACTIVE_PROCESSES.discard(process)
                KILLED_PROCESSES.discard(process)
    status["duration_seconds"] = round(time.monotonic() - started, 2)
    statuses.append(status)
    if status["status"] != "success":
        print(f"::warning::{name}: {status['status']}; see pipeline diagnostics")
    return status["status"] == "success"


def source_status(output, command_ok):
    """Exit code, schema, metadata and subsource results all contribute to health."""
    valid, errors = validate_file(output, "raw_item")
    if not valid:
        return "failed", {"errors": errors[:10]}, False
    payload = json.loads(output.read_text())
    items = payload.get("items", []) if isinstance(payload, dict) else payload
    meta = payload.get("meta", {}) if isinstance(payload, dict) else {}
    if not isinstance(meta, dict):
        return "failed", {"errors": ["Invalid source metadata"]}, False
    children = []
    diagnostic_errors = []
    for suffix in ("_status.json", "_errors.json"):
        companion = output.with_name(output.stem + suffix)
        if companion.exists():
            records = json.loads(companion.read_text())
            if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
                return "failed", {"errors": ["Invalid source diagnostics"]}, False
            if suffix == "_status.json":
                children = records
            else:
                diagnostic_errors = records
    status = meta.get("status")
    if children:
        bad = sum(row.get("status") in {"failed", "timeout"} for row in children)
        partial = any(row.get("status") == "partial" for row in children)
        status = "failed" if bad == len(children) else "partial" if bad or partial else "success" if items else "no_new"
    elif diagnostic_errors and not status:
        status = "partial" if items else "failed"
    if not command_ok and status != "partial":
        status = "failed"
    status = status or ("success" if items else "no_new")
    if status not in {"success", "partial", "no_new", "not_found", "failed", "timeout"}:
        status = "failed"
    usable = status in {"success", "partial", "no_new", "not_found"}
    return status, {**meta, "item_count": len(items), "subsources": children,
                    "errors": meta.get("errors", diagnostic_errors)}, usable


def _run_pipeline(work, reports, statuses, *, mock, source_timeout, llm_timeout):
    data = PROJECT_ROOT / "data"
    raw, processed, daily, state = (work / name for name in ("raw", "processed", "daily", "state"))
    for directory in (raw, processed, daily, state):
        directory.mkdir()
    env = os.environ.copy()
    env["LLM_MOCK"] = "1" if mock else "0"
    pointer = storage.read_snapshot(data)
    previous = data / pointer["digest"] if pointer else data / "daily/latest.json"
    saved_index = data / pointer["index"] if pointer else data / "daily/index.json"
    saved_state = data / pointer["state"] if pointer else data / "state"
    if previous.exists() and not validate_file(previous, "digest")[0]:
        if pointer:
            raise ValueError("Authoritative snapshot is invalid")
        previous = None  # Ignore unvalidated legacy placeholders, never an authoritative generation.
    if saved_state.exists():
        shutil.copytree(saved_state, state, dirs_exist_ok=True)
    if saved_index.exists():
        shutil.copy2(saved_index, daily / "index.json")

    sources = [
        ("arxiv", "fetch_arxiv.py", "arxiv_latest.json", ["--max-results", "100"], None),
        ("conferences", "fetch_top_conferences.py", "top_conferences.json",
         ["--limit-per-conf", "5", "--state-file", str(state / "dblp_state.json")], "dblp_state.json"),
        ("kev", "fetch_cisa_kev.py", "cisa_kev.json", ["--days", "1"], None),
        ("nvd", "fetch_nvd.py", "nvd_recent.json",
         ["--days", "1", "--state-file", str(state / "nvd_cursor.json")], "nvd_cursor.json"),
        ("ghsa", "fetch_github_advisory.py", "github_advisory_latest.json", [], None),
        ("vendor", "fetch_vendor_advisories.py", "vendor_advisories.json",
         ["--days", "1", "--limit-per-source", "50", "--state-file", str(state / "vendor_seen.json")], "vendor_seen.json"),
        ("threat", "fetch_threat_intel.py", "threat_intel.json",
         ["--days", "1", "--limit-per-source", "50", "--state-file", str(state / "threat_seen.json")], "threat_seen.json"),
    ]
    enrichment = [
        ("epss", "fetch_epss.py", "epss_scores.json",
         ["--input", str(raw / "cisa_kev.json"), "--input", str(raw / "nvd_recent.json")], None),
        ("osv", "fetch_osv.py", "osv_latest.json",
         ["--nvd-source", str(raw / "nvd_recent.json"), "--limit", "500"], None),
    ]
    health = {"checked_at": datetime.now(timezone.utc).isoformat(), "sources": {}}

    def fetch(source):
        name, script, filename, options, state_name = source
        local_steps = []
        output = raw / filename
        ok = run_command(f"fetch-{name}", [f"scripts/{script}", *options, "--output", str(output)],
                         reports, local_steps, timeout=source_timeout, env=env)
        status, details, usable = source_status(output, ok)
        if local_steps:
            local_steps[-1]["status"] = status if usable or ok else local_steps[-1]["status"]
        for companion in output.parent.glob(output.stem + "_*.json"):
            shutil.copy2(companion, reports / companion.name)
        if not usable:
            storage.atomic_json(output, {"items": []})
            if state_name:
                destination = state / state_name
                destination.unlink(missing_ok=True)
                if (saved_state / state_name).exists():
                    shutil.copy2(saved_state / state_name, destination)
        return name, status, details, local_steps

    for batch in (sources, enrichment):
        with ThreadPoolExecutor(max_workers=4) as executor:
            try:
                for name, status, details, steps in executor.map(fetch, batch):
                    statuses.extend(steps)
                    health["sources"][name] = {**details, "status": status}
            except BaseException:
                cancel_processes()
                raise
    if not any(health["sources"][name]["status"] in {"success", "partial", "no_new", "not_found"}
               for name, *_ in sources):
        statuses.append({"name": "publish", "status": "all_sources_failed"})
        return False

    # Unknown publication dates use persistent discovery time across every channel.
    unknown_state = state / "first_seen_unknown.json"
    discoveries = json.loads(unknown_state.read_text()) if unknown_state.exists() else {}
    for path in raw.glob("*.json"):
        if path.name.endswith(("_status.json", "_errors.json")):
            continue
        payload = json.loads(path.read_text())
        records = payload.get("items", []) if isinstance(payload, dict) else payload
        changed = False
        for record in records:
            if record.get("published_at") is not None:
                continue
            first = discoveries.get(record["id"]) or record.get("first_seen_at") or record["fetched_at"]
            first = datetime.fromisoformat(first.replace("Z", "+00:00")).isoformat()
            discoveries[record["id"]] = first
            record["first_seen_at"] = first
            if record.get("date_precision", "exact") == "exact":
                record["date_precision"] = "unknown"
            changed = True
        if changed:
            storage.atomic_json(path, payload)
    storage.atomic_json(unknown_state, dict(sorted(discoveries.items(), key=lambda row: row[1], reverse=True)[:20000]))

    groups = [
        ("paper_digest.json", ["arxiv_latest.json", "top_conferences.json"], 30),
        ("daily_digest.json", ["cisa_kev.json", "nvd_recent.json", "github_advisory_latest.json", "osv_latest.json"], 20),
        ("vendor_advisories_digest.json", ["vendor_advisories.json"], 30),
        ("threat_intel_digest.json", ["threat_intel.json"], 30),
    ]
    summary_stats = []
    deadline = time.monotonic() + llm_timeout
    if mock or env.get("OPENAI_API_KEY"):
        for filename, inputs, limit in groups:
            output = processed / filename
            options = [part for source in inputs for part in ("--input", str(raw / source))]
            remaining = max(0, deadline - time.monotonic())
            options += ["--limit", str(limit), "--cache-file", str(state / "llm_cache.json"),
                        "--circuit-file", str(work / "llm_circuit.json"), "--budget-seconds", str(remaining)]
            if mock:
                options.append("--mock")
            ok = run_command(f"summarize-{output.stem}",
                             ["scripts/summarize_with_llm.py", *options, "--output", str(output)],
                             reports, statuses, timeout=max(1, min(llm_timeout, remaining + 45)), env=env)
            if not ok or not validate_file(output, "digest")[0]:
                output.unlink(missing_ok=True)
            else:
                summary_stats.append(json.loads(output.read_text()).get("summary_stats", {}))
    else:
        statuses.append({"name": "summarize", "status": "source_excerpts"})
    health["llm"] = {"groups": summary_stats, "circuit": json.loads((work / "llm_circuit.json").read_text())
                     if (work / "llm_circuit.json").exists() else None}
    health["status"] = "degraded" if any(
        row["status"] in {"failed", "timeout", "partial"} for row in health["sources"].values()) else "healthy"
    storage.atomic_json(work / "health.json", health)
    options = ["scripts/build_daily_digest.py", "--raw-dir", str(raw), "--processed-dir", str(processed),
               "--output-dir", str(daily), "--health-file", str(work / "health.json")]
    if previous:
        options += ["--previous-digest", str(previous)]
    if not run_command("build-digest", options, reports, statuses, timeout=90, env=env):
        return False
    latest = daily / "latest.json"
    ok, errors = validate_file(latest, "digest")
    if not ok:
        statuses.append({"name": "validate-digest", "status": "failed", "errors": errors[:20]})
        return False
    digest = json.loads(latest.read_text())
    index = json.loads((daily / "index.json").read_text())
    current = storage.publish_snapshot(data, digest, index, state)
    statuses.append({"name": "publish", "status": "success", "generation": current["generation"]})
    # Flat files are compatibility mirrors; readers use current.json as the authority.
    try:
        for path in (data / "daily/latest.json", data / "daily" / f"{digest['date']}.json"):
            storage.atomic_json(path, digest)
        storage.atomic_json(data / "daily/index.json", index)
        for staged, destination in ((raw, data / "raw"), (processed, data / "processed"), (state, data / "state")):
            destination.mkdir(parents=True, exist_ok=True)
            if staged in (processed, state):
                for old in destination.glob("*.json"):
                    if not (staged / old.name).exists():
                        old.unlink()
            for path in staged.glob("*.json"):
                if not path.name.endswith(("_errors.json", "_status.json")):
                    storage.atomic_json(destination / path.name, json.loads(path.read_text()))
    except OSError as exc:
        statuses.append({"name": "compatibility-mirror", "status": "warning", "error_type": type(exc).__name__})
    return True


def run_pipeline(work, reports, statuses, *, mock, source_timeout, llm_timeout):
    try:
        with storage.snapshot_lock(PROJECT_ROOT / "data"):
            with process_guard():
                CANCELLED.clear()
            return _run_pipeline(work, reports, statuses, mock=mock,
                                 source_timeout=source_timeout, llm_timeout=llm_timeout)
    except (OSError, ValueError, RuntimeError) as exc:
        statuses.append({"name": "pipeline", "status": "failed", "error_type": type(exc).__name__})
        print(f"::error::Pipeline failed: {type(exc).__name__}")
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--source-timeout", type=int, default=240)
    parser.add_argument("--llm-timeout", type=int, default=120, help="Total optional summary budget")
    parser.add_argument("--reports-dir", type=Path, default=PROJECT_ROOT / "data/tmp/pipeline")
    args = parser.parse_args()
    if min(args.source_timeout, args.llm_timeout) <= 0:
        parser.error("Timeouts must be positive")
    reports = args.reports_dir.resolve()
    reports.mkdir(parents=True, exist_ok=True)
    statuses, success = [], False
    scratch = PROJECT_ROOT / "data/tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="pipeline-", dir=scratch) as directory:
            success = run_pipeline(Path(directory), reports, statuses, mock=args.mock,
                                   source_timeout=args.source_timeout, llm_timeout=args.llm_timeout)
    finally:
        storage.atomic_json(reports / "status.json", {
            "generated_at": datetime.now(timezone.utc).isoformat(), "success": success, "steps": statuses})
        if os.getenv("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out:
                out.write("### Daily pipeline\n\n| Step | Status |\n| --- | --- |\n")
                for step in statuses:
                    out.write(f"| {step['name']} | {step['status']} |\n")
    return 0 if success else 1


if __name__ == "__main__":
    # Propagate cancellation through subprocess groups and the snapshot lock.
    signal.signal(signal.SIGTERM, terminate_pipeline)
    sys.exit(main())
