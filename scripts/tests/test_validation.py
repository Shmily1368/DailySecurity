import json

import pytest

import validate_data as m
from models import DailyDigest, Hero, HeroStats
from test_builder import digest
from test_llm import raw_item


@pytest.mark.parametrize("case", ["new_raw", "new_digest", "empty_intermediate", "malformed",
                                 "bad_date", "missing_section_item", "duplicate_id", "bad_cve", "empty_title"])
def test_file_validation(tmp_path, case):
    path = tmp_path / "input.json"
    raw = raw_item().model_dump(mode="json")
    item = digest()
    payload = DailyDigest(date="2026-10-29", generated_at=item.fetched_at,
                          hero=Hero(one_liner_zh="情报", stats=HeroStats()),
                          sections={"top_10": [item.id]}, items=[item]).model_dump(mode="json")
    valid = case in {"new_raw", "new_digest", "empty_intermediate"}
    schema = "digest"
    if case == "new_raw":
        raw["published_at"] = None
        raw["date_precision"] = "unknown"
        payload = {"items": [raw], "meta": {"status": "success"}}
        schema = "raw_item"
    elif case == "empty_intermediate":
        payload = {"kind": "digest_items", "items": []}
    elif case == "bad_date":
        payload["date"] = "2026-02-31"
    elif case == "missing_section_item":
        payload["sections"]["top_10"].append("absent:item")
    elif case == "duplicate_id":
        payload["items"].append(payload["items"][0])
    elif case in {"bad_cve", "empty_title"}:
        schema = "raw_item"
        raw["cves"] = ["CVE-2026-1"] if case == "bad_cve" else raw["cves"]
        raw["title"] = "" if case == "empty_title" else raw["title"]
        payload = {"items": [raw]}
    path.write_text("{broken" if case == "malformed" else json.dumps(payload))
    ok, errors = m.validate_file(path, schema)
    assert ok is valid, errors
    assert bool(errors) is not valid


def test_collect_excludes_diagnostics(tmp_path, monkeypatch):
    for name in ("index.json", "feed_errors.json", "feed_status.json", "error_related_items.json"):
        (tmp_path / name).write_text("{}")
    monkeypatch.setattr(m, "DEFAULT_DIRS", [tmp_path])
    assert [p.name for p in m._collect_all_files()] == ["error_related_items.json"]
