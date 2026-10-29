import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import run_pipeline as m
import storage
from models import ItemType
from test_llm import raw_item
from validate_data import validate_file


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "project"
    (root / "data/daily").mkdir(parents=True)
    (root / "scripts").symlink_to(m.PROJECT_ROOT / "scripts", target_is_directory=True)
    (root / "data/state").mkdir()
    (root / "data/state/dblp_state.json").write_text('{"seen_keys":["existing"]}')
    (root / "data/daily/latest.json").write_text('{"previous":"legacy"}')
    (root / "data/daily/index.json").write_text('{"dates":["2020-01-01"],"latest":"2020-01-01"}')
    monkeypatch.setattr(m, "PROJECT_ROOT", root)
    return root


def run_fixture(project, monkeypatch, *, empty=False, failed=False, errors=False, paper=False, unknown_date=False):
    reports = project / "reports"
    reports.mkdir(exist_ok=True)
    work = project / ("work-" + str(len(list(project.glob("work-*")))))
    work.mkdir()
    original = m.run_command

    def command(name, args, reports, statuses, *, timeout, env):
        if name == "build-digest":
            return original(name, args, reports, statuses, timeout=timeout, env=env)
        output = Path(args[args.index("--output") + 1])
        output.parent.mkdir(exist_ok=True)
        if name.startswith("summarize-"):
            assert env.get("OPENAI_API_KEY") == "fixture-key"
            output.write_text('{"items":[{"id":"failed"}]}')
            statuses.append({"name": name, "status": "timeout"})
            return False
        entries = []
        if name == "fetch-nvd" and not empty and not failed:
            item = raw_item()
            if unknown_date:
                item.published_at = None
                item.first_seen_at = item.fetched_at
                item.date_precision = "unknown"
            entries = [item.model_dump(mode="json")]
        if name == "fetch-conferences":
            state = Path(args[args.index("--state-file") + 1])
            state.write_text('{"seen_keys":["existing","new-paper"]}')
            if paper:
                item = raw_item(10, kind=ItemType.PAPER)
                item.id = "paper:new-paper"
                entries = [item.model_dump(mode="json")]
        output.write_text(json.dumps({"items": entries}))
        if errors and name == "fetch-vendor":
            output.with_name(output.stem + "_errors.json").write_text('[{"source_id":"all","error":"timeout"}]')
        statuses.append({"name": name, "status": "failed" if failed else "success"})
        return not failed

    statuses = []
    with monkeypatch.context() as patch:
        patch.setattr(m, "run_command", command)
        patch.setenv("OPENAI_API_KEY", "fixture-key")
        ok = m.run_pipeline(work, reports, statuses, mock=False, source_timeout=5, llm_timeout=5)
    return ok, statuses


@pytest.mark.parametrize("case", ["fallback", "no_new", "all_failed", "subsource_errors"])
def test_publish_outcome(project, monkeypatch, case):
    ok, steps = run_fixture(project, monkeypatch, empty=case == "no_new",
                            failed=case == "all_failed", errors=case == "subsource_errors")
    if case == "all_failed":
        assert not ok
        assert json.loads((project / "data/daily/latest.json").read_text()) == {"previous": "legacy"}
        assert not (project / "data/current.json").exists()
        return
    assert ok
    if case == "subsource_errors":
        assert any(s["name"] == "fetch-vendor" and s["status"] == "failed" for s in steps)
    current = json.loads((project / "data/current.json").read_text())
    digest_path = project / "data" / current["digest"]
    assert validate_file(digest_path, "digest")[0]
    digest = json.loads(digest_path.read_text())
    assert digest["is_mock"] is False
    assert len(digest["items"]) == (0 if case == "no_new" else 1)
    if case == "subsource_errors":
        assert any(s["name"] == "fetch-vendor" and s["status"] == "failed" for s in steps)
    if case == "fallback":
        assert digest["items"][0]["summary_status"] == "excerpt"
    assert "2020-01-01" in json.loads((project / "data" / current["index"]).read_text())["dates"]


def test_same_day_replay_keeps_papers(project, monkeypatch):
    assert run_fixture(project, monkeypatch, paper=True)[0]
    assert run_fixture(project, monkeypatch)[0]
    flat = json.loads((project / "data/daily/latest.json").read_text())
    assert "paper:new-paper" in {i["id"] for i in flat["items"]}
    pointer = json.loads((project / "data/current.json").read_text())
    digest = json.loads((project / "data" / pointer["digest"]).read_text())
    assert "paper:new-paper" in {i["id"] for i in digest["items"]}
    state = json.loads((project / "data" / pointer["state"] / "dblp_state.json").read_text())
    assert "new-paper" in state["seen_keys"]


@pytest.mark.parametrize("stage", ["generation", "pointer"])
def test_interrupted_publication_preserves_previous(project, monkeypatch, stage):
    assert run_fixture(project, monkeypatch)[0]
    current = (project / "data/current.json").read_bytes()
    pointer = json.loads(current)
    previous = (project / "data" / pointer["digest"]).read_bytes()
    original = storage.atomic_json

    def interrupted(path, payload):
        path = Path(path)
        if stage == "pointer" and path.name == "current.json":
            raise OSError("disk full")
        if stage == "generation" and path.name == "digest.json":
            raise OSError("disk full")
        return original(path, payload)

    monkeypatch.setattr(storage, "atomic_json", interrupted)
    if hasattr(m, "atomic_json"):
        monkeypatch.setattr(m, "atomic_json", interrupted)
    assert not run_fixture(project, monkeypatch)[0]
    assert (project / "data/current.json").read_bytes() == current
    assert (project / "data" / pointer["digest"]).read_bytes() == previous
    assert validate_file(project / "data" / pointer["digest"], "digest")[0]


def test_snapshot_excludes_second_writer(tmp_path):
    with storage.snapshot_lock(tmp_path):
        with pytest.raises(RuntimeError, match="already running"):
            with storage.snapshot_lock(tmp_path):
                pytest.fail("Concurrent state updates must not proceed")


def test_unknown_date_keeps_first_discovery(project, monkeypatch):
    assert run_fixture(project, monkeypatch, unknown_date=True)[0]
    first = json.loads((project / "data/daily/latest.json").read_text())["items"][0]
    assert run_fixture(project, monkeypatch, unknown_date=True)[0]
    second = json.loads((project / "data/daily/latest.json").read_text())["items"][0]
    assert second["first_seen_at"] == first["first_seen_at"]
    assert second["published_at"] is None


def test_timeout_reaps_descendants(tmp_path):
    pidfile = tmp_path / "child.pid"
    source = tmp_path / "process.py"
    source.write_text(
        "import subprocess, sys, time\nfrom pathlib import Path\n"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\n"
        f"Path({str(pidfile)!r}).write_text(str(p.pid))\ntime.sleep(30)\n"
    )
    statuses = []
    assert not m.run_command("cancel", [str(source)], tmp_path, statuses, timeout=1, env=os.environ.copy())
    assert statuses[-1]["status"] == "timeout"
    child = int(pidfile.read_text())
    result = subprocess.run(["ps", "-o", "stat=", "-p", str(child)], capture_output=True, text=True)
    assert result.returncode != 0 or result.stdout.strip().startswith("Z")


def test_final_health_rejects_failed_process_metadata(project, monkeypatch):
    original = m.source_status

    def status(output, command_ok):
        if output.name == "vendor_advisories.json":
            return "failed", {"status": "success", "item_count": 0}, False
        return original(output, command_ok)

    monkeypatch.setattr(m, "source_status", status)
    assert run_fixture(project, monkeypatch)[0]
    pointer = storage.read_snapshot(project / "data")
    assert pointer["health"]["sources"]["vendor"]["status"] == "failed"
    assert pointer["health"]["status"] == "degraded"


def test_partial_subsource_is_degraded(tmp_path):
    output = tmp_path / "source.json"
    output.write_text('{"items":[],"meta":{"status":"success"}}')
    output.with_name("source_status.json").write_text('[{"status":"partial"}]')
    status, _, usable = m.source_status(output, True)
    assert status == "partial" and usable


@pytest.mark.parametrize("fail_archive", [False, True])
def test_rollover_archives_final_generation(project, monkeypatch, fail_archive):
    assert run_fixture(project, monkeypatch)[0]
    data = project / "data"
    previous = storage.read_snapshot(data)
    digest = json.loads((data / previous["digest"]).read_text())
    # Simulate a stale or missing same-day mirror after an otherwise successful commit.
    mirror = data / "daily" / f"{digest['date']}.json"
    mirror.unlink()
    next_date = "2099-01-01"
    next_digest = {**digest, "date": next_date}
    index = {"latest": next_date, "dates": [next_date, digest["date"]]}
    original = storage.atomic_json

    def write(path, payload):
        if fail_archive and Path(path) == mirror:
            raise OSError("archive unavailable")
        return original(path, payload)

    with monkeypatch.context() as patch:
        patch.setattr(storage, "atomic_json", write)
        if fail_archive:
            with pytest.raises(OSError, match="archive unavailable"):
                storage.publish_snapshot(data, next_digest, index, data / previous["state"])
            assert storage.read_snapshot(data) == previous
        else:
            storage.publish_snapshot(data, next_digest, index, data / previous["state"])
            assert json.loads(mirror.read_text()) == digest
            assert validate_file(mirror, "digest")[0]
    if fail_archive:
        storage.publish_snapshot(data, next_digest, index, data / previous["state"])
        assert json.loads(mirror.read_text()) == digest


def test_cancelled_worker_cannot_launch(tmp_path, monkeypatch):
    arrived, release = threading.Event(), threading.Event()
    original_open = Path.open
    launched = []

    def paused_open(path, *args, **kwargs):
        if path.name == "queued.log":
            arrived.set()
            assert release.wait(5)
        return original_open(path, *args, **kwargs)

    def forbidden_launch(*args, **kwargs):
        launched.append(args)
        pytest.fail("A dequeued worker must not start after cancellation")

    def worker():
        try:
            m.run_command("queued", ["unused.py"], tmp_path, [], timeout=1, env={})
        except SystemExit as exc:
            assert exc.code == 143

    monkeypatch.setattr(Path, "open", paused_open)
    monkeypatch.setattr(m.subprocess, "Popen", forbidden_launch)
    m.CANCELLED.clear()
    thread = threading.Thread(target=worker)
    thread.start()
    assert arrived.wait(5)
    try:
        m.cancel_processes()
        release.set()
        thread.join(5)
        assert not thread.is_alive()
        assert not launched and not m.ACTIVE_PROCESSES
    finally:
        release.set()
        thread.join(5)
        m.CANCELLED.clear()


def test_sigterm_during_main_thread_launch_reaps_process(tmp_path):
    script = tmp_path / "signal_during_launch.py"
    script.write_text(
        "import os, signal, sys\nfrom pathlib import Path\n"
        f"sys.path.insert(0, {str(Path(m.__file__).parent)!r})\n"
        "import run_pipeline as m\n"
        "signal.signal(signal.SIGTERM, m.terminate_pipeline)\n"
        "original = m.subprocess.Popen\n"
        "def interrupted(*args, **kwargs):\n"
        "    process = original(*args, **kwargs)\n"
        "    os.kill(os.getpid(), signal.SIGTERM)\n"
        "    return process\n"
        "m.subprocess.Popen = interrupted\n"
        "try:\n"
        f"    m.run_command('main', ['-c', 'import time;time.sleep(30)'], Path({str(tmp_path)!r}), [], timeout=10, env=os.environ.copy())\n"
        "except SystemExit as exc:\n"
        "    assert exc.code == 143 and not m.ACTIVE_PROCESSES\n"
        "else:\n"
        "    raise AssertionError('SIGTERM must abort the command')\n"
    )
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("method", ["clear", "set"])
def test_sigterm_cannot_reenter_event_lock(tmp_path, method):
    script = tmp_path / f"signal_event_{method}.py"
    script.write_text(
        "import os, signal, sys, threading\nfrom pathlib import Path\n"
        f"sys.path.insert(0, {str(Path(m.__file__).parent)!r})\n"
        "import run_pipeline as m\n"
        "signal.signal(signal.SIGTERM, m.terminate_pipeline)\n"
        f"m.PROJECT_ROOT = Path({str(tmp_path)!r})\n"
        "m._run_pipeline = lambda *args, **kwargs: True\n"
        "fired = False\n"
        "def trace(frame, event, arg):\n"
        "    global fired\n"
        f"    if not fired and event == 'line' and frame.f_code is threading.Event.{method}.__code__ and frame.f_locals.get('self') is m.CANCELLED and m.CANCELLED._cond._lock.locked():\n"
        "        fired = True\n"
        "        os.kill(os.getpid(), signal.SIGTERM)\n"
        "    return trace\n"
        "sys.settrace(trace)\n"
        "try:\n"
        + ("    m.run_pipeline(m.PROJECT_ROOT/'work', m.PROJECT_ROOT/'reports', [], mock=False, source_timeout=1, llm_timeout=1)\n"
           if method == "clear" else "    m.cancel_processes()\n")
        + "except SystemExit as exc:\n"
        "    assert exc.code == 143\n"
        "else:\n"
        "    raise AssertionError('Signal must cancel after the protected Event operation')\n"
        "sys.settrace(None)\n"
        "assert fired\n"
        "with m.storage.snapshot_lock(m.PROJECT_ROOT/'data'):\n"
        "    pass\n"
    )
    result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr
