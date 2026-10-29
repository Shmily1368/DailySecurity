"""Filesystem primitives used by source state and snapshot publication."""
import json
import os
import tempfile
import fcntl
import hashlib
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, payload, *, indent=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(payload, out, ensure_ascii=False,
                      separators=(",", ":") if indent is None else None, sort_keys=True, indent=indent)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def snapshot_lock(data_dir):
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".pipeline.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Daily pipeline already running") from exc
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def read_snapshot(data_dir):
    directory = Path(data_dir).resolve()
    path = directory / "current.json"
    if not path.exists():
        return None
    current = json.loads(path.read_text())
    for key in ("digest", "index", "state"):
        target = (directory / current[key]).resolve()
        if not target.is_relative_to(directory / "generations") or not target.exists():
            raise ValueError(f"Invalid snapshot {key}")
    digest = directory / current["digest"]
    if hashlib.sha256(digest.read_bytes()).hexdigest() != current["sha256"]:
        raise ValueError("Snapshot checksum mismatch")
    return current


def publish_snapshot(data_dir, digest, index, state):
    """The pointer is the commit point; failed preparation never touches the old generation."""
    directory = Path(data_dir)
    generations = directory / "generations"
    generations.mkdir(parents=True, exist_ok=True)
    previous = read_snapshot(directory)
    generation_id = digest["date"] + "-" + uuid.uuid4().hex[:16]
    final = generations / generation_id
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=generations))
    try:
        atomic_json(staging / "digest.json", digest)
        atomic_json(staging / "index.json", index)
        (staging / "state").mkdir()
        for path in Path(state).glob("*.json"):
            atomic_json(staging / "state" / path.name, json.loads(path.read_text()))
        from validate_data import validate_file
        valid, errors = validate_file(staging / "digest.json", "digest")
        if not valid:
            raise ValueError(f"Invalid generation: {errors[:3]}")
        # Freeze the final authoritative edition before making its date historical.
        # Its same-day compatibility mirror may have failed or become stale.
        previous_digest = directory / previous["digest"] if previous else directory / "daily/latest.json"
        if previous_digest.exists():
            archived = json.loads(previous_digest.read_text())
            if (archived.get("date") != digest["date"] and archived.get("date") in index.get("dates", [])):
                valid, errors = validate_file(previous_digest, "digest")
                if not valid:
                    raise ValueError(f"Invalid previous edition: {errors[:3]}")
                atomic_json(directory / "daily" / f"{archived['date']}.json", archived)
        sync_directory(staging)
        os.replace(staging, final)
        sync_directory(generations)
        base = f"generations/{generation_id}"
        pointer = {
            "generation": generation_id, "date": digest["date"],
            "generated_at": digest["generated_at"], "item_count": len(digest["items"]),
            "digest": base + "/digest.json", "index": base + "/index.json",
            "state": base + "/state",
            "sha256": hashlib.sha256((final / "digest.json").read_bytes()).hexdigest(),
            "health": digest.get("health", {}),
        }
        try:
            atomic_json(directory / "current.json", pointer)
        except OSError:
            # os.replace is the commit point. A later directory-sync failure cannot uncommit it.
            if not (directory / "current.json").exists() or json.loads(
                    (directory / "current.json").read_text()) != pointer:
                raise
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        # A renamed but uncommitted generation is safe to discard.
        if final.exists() and (not (directory / "current.json").exists()
                               or json.loads((directory / "current.json").read_text()).get("generation") != generation_id):
            shutil.rmtree(final, ignore_errors=True)
        raise
    # Cleanup is optional once the pointer is committed.
    retained = {generation_id, previous["generation"] if previous else ""}
    for path in generations.iterdir():
        if path.name not in retained:
            shutil.rmtree(path, ignore_errors=True)
    return pointer
