import json
from datetime import datetime, timedelta, timezone
from itertools import product
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

import build_daily_digest as m
import validate_data as validator
from fetch_github_advisory import entry_to_raw_item as normalize_ghsa
from models import ItemType, RiskSignal, SourceInfo
from summarize_with_llm import build_digest_item, build_llm_summary
from test_llm import raw_item


def digest(index=0, source="nvd", risk=None, kind=ItemType.CVE):
    raw = raw_item(index, kind=kind)
    raw.source_info.source = source
    if risk:
        raw.risk = risk
    return build_digest_item(raw, build_llm_summary(raw, {"prompt_version": "fallback"}))


@pytest.mark.parametrize("source,risk,section", [
    ("nvd", RiskSignal(has_public_exploit=True, exploit_maturity="poc"), "vuln_poc"),
    ("nvd", RiskSignal(known_exploited=True, exploit_maturity="in_the_wild"), "vuln_exploited"),
    ("ghsa", RiskSignal(), "vuln_baseline"),
])
def test_risk_sections(source, risk, section):
    item = digest(source=source, risk=risk, kind=ItemType.ADVISORY if source == "ghsa" else ItemType.CVE)
    sections = m.build_sections([item], top_10_ids=[])
    assert item.id in sections[section]


def test_top_entity_quota():
    duplicate = [digest(source=s, kind=ItemType.ADVISORY) for s in ("nvd", "ghsa", "osv")]
    for item in duplicate:
        item.id = item.source + ":" + item.id
    unique = [digest(i) for i in range(1, 5)]
    top = m.get_diverse_top_10(duplicate + unique)
    assert len([i for i in top if i.cves == ["CVE-2026-1234"]]) == 1


def test_source_merge(tmp_path):
    items = [digest(source=s, kind=ItemType.ADVISORY) for s in ("nvd", "ghsa", "osv")]
    for item in items:
        item.id = item.source + ":" + item.id
    (tmp_path / "daily.json").write_text(json.dumps({"items": [i.model_dump(mode="json") for i in items]}))
    result = m.load_processed_items(str(tmp_path))
    assert len(result) == 1
    item = next(iter(result.values()))
    assert {i.source for i in item.related_sources} | {item.source} == {"nvd", "ghsa", "osv"}


def test_local_builder_does_not_call_optional_api(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-key")
    client = Mock(side_effect=AssertionError("Optional API must be outside required assembly"))
    with patch.object(m, "OpenAiLlmClient", client):
        item = digest()
        assert m.process_missing_top_items_with_llm([item], str(tmp_path)) == [item]
    client.assert_not_called()


def test_fallback_uses_updated_window(tmp_path):
    raw = raw_item()
    raw.published_at = raw.published_at.replace(year=2020)
    raw.updated_at = raw.fetched_at
    (tmp_path / "nvd.json").write_text(json.dumps({"items": [raw.model_dump(mode="json")]}))
    result = m.load_missing_raw_items(str(tmp_path), set())
    assert len(result) == 1
    assert result[0].summary_status == "excerpt"


def test_fallback_rejects_navigation(tmp_path):
    raw = raw_item()
    raw.source_info.source = "vendor"
    raw.source_info.source_url = "https://beian.miit.gov.cn/"
    raw.title = "京ICP证080047号[京ICP备08010314号-6]"
    (tmp_path / "vendor.json").write_text(json.dumps({"items": [raw.model_dump(mode="json")]}))
    assert m.load_missing_raw_items(str(tmp_path), set()) == []


BUILDER_NOW = datetime(2026, 10, 29, 1, tzinfo=timezone.utc)


def builder_raw(source, when, risk=None, kind=ItemType.CVE):
    raw = raw_item(kind=kind)
    raw.id = f"{source}:CVE-2026-1234"
    raw.source_info = SourceInfo(
        source=source, source_name=source.upper(), source_quality="primary",
        source_url=f"https://example.org/{source}/CVE-2026-1234",
        native_id="CVE-2026-1234",
    )
    raw.published_at = when
    raw.updated_at = when if source == "nvd" else None
    raw.fetched_at = raw.first_seen_at = BUILDER_NOW
    raw.cves = [] if kind == ItemType.PAPER else ["CVE-2026-1234"]
    if risk is not None:
        raw.risk = risk
    return raw


def builder_summary(raw, *, excerpt=False):
    return build_digest_item(raw, build_llm_summary(raw, {
        "summary_zh": raw.summary or raw.title,
        "why_it_matters_zh": "Source-supported reason",
        "novelty_score": 0.4,
        "actionability_score": 0.4,
        **({"prompt_version": "fallback"} if excerpt else {}),
    }))


@pytest.fixture
def run_builder(tmp_path, monkeypatch):
    processed_dir, raw_dir = tmp_path / "processed", tmp_path / "raw"
    processed_dir.mkdir()
    raw_dir.mkdir()
    monkeypatch.setenv("LLM_MOCK", "0")

    def run(*, processed=(), raw_items=(), previous=None, clock=BUILDER_NOW, health=None):
        (processed_dir / "daily_digest.json").write_text(json.dumps({
            "items": [item.model_dump(mode="json") for item in processed],
        }))
        (raw_dir / "nvd_recent.json").write_text(json.dumps({
            "items": [item.model_dump(mode="json") for item in raw_items],
        }))
        previous_path = tmp_path / "previous.json"
        if previous is not None:
            previous_path.write_text(json.dumps(previous))
        health_path = tmp_path / "health.json"
        health_path.write_text(json.dumps(
            health if health is not None else {"sources": {"nvd": {"status": "success"}}}
        ))
        args = SimpleNamespace(
            processed_dir=processed_dir, raw_dir=raw_dir, output_dir=tmp_path / "daily",
            previous_digest=previous_path if previous is not None else None,
            health_file=health_path, date=None,
        )

        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock.astimezone(tz) if tz else clock.replace(tzinfo=None)

        monkeypatch.setattr(m, "datetime", FrozenDatetime)
        monkeypatch.setattr(m, "parse_args", lambda: args)
        assert m.main() == 0
        output = json.loads((args.output_dir / "latest.json").read_text())
        assert validator._validate_digest(output) == []
        assert validator._jsonschema_check(output, validator._load_schema("digest")) == []
        return output

    return run


def test_processed_loading_can_defer_aggregation(tmp_path):
    items = [builder_summary(builder_raw(source, BUILDER_NOW)) for source in ("nvd", "kev")]
    (tmp_path / "daily.json").write_text(json.dumps({
        "items": [item.model_dump(mode="json") for item in items],
    }))
    assert len(m.load_processed_items(str(tmp_path))) == 1
    assert set(m.load_processed_items(str(tmp_path), aggregate=False)) == {item.id for item in items}


@pytest.mark.parametrize("source", ["vendor", "ghsa"])
@pytest.mark.parametrize("processed", [False, True])
def test_unknown_publication_preserves_known_revision(run_builder, source, processed):
    event = builder_raw(source, BUILDER_NOW - timedelta(days=30), kind=ItemType.ADVISORY)
    event.published_at = None
    event.date_precision = "unknown"
    event.first_seen_at = BUILDER_NOW - timedelta(days=30)
    event.updated_at = BUILDER_NOW - timedelta(hours=1)
    output = run_builder(processed=[builder_summary(event)] if processed else [],
                         raw_items=[] if processed else [event])
    assert len(output["items"]) == 1
    assert output["items"][0]["published_at"] is None
    assert output["items"][0]["updated_at"] == event.updated_at.isoformat().replace("+00:00", "Z")


@pytest.mark.parametrize("inputs", ["processed", "mixed", "raw"])
def test_recent_kev_is_windowed_before_aggregation(run_builder, inputs):
    old = builder_raw("nvd", BUILDER_NOW - timedelta(days=3))
    recent = builder_raw("kev", BUILDER_NOW - timedelta(hours=1), RiskSignal(
        kev_listed=True, kev_status="listed", known_exploited=True, known_ransomware=True,
    ), kind=ItemType.KEV)
    if inputs == "processed":
        output = run_builder(processed=[builder_summary(old), builder_summary(recent)], raw_items=[old, recent])
    elif inputs == "mixed":
        output = run_builder(processed=[builder_summary(old)], raw_items=[old, recent])
    else:
        output = run_builder(raw_items=[old, recent])
    assert len(output["items"]) == 1
    item = output["items"][0]
    assert item["id"] == recent.id
    assert item["published_at"] == recent.published_at.isoformat().replace("+00:00", "Z")
    assert item["risk"]["kev_listed"] is True
    assert item["risk"]["known_ransomware"] is True
    assert old.id not in item["aliases"]
    assert output["sections"]["vuln_exploited"] == [recent.id]


@pytest.mark.parametrize("source,kind,hours", [
    ("nvd", ItemType.CVE, 36),
    ("arxiv", ItemType.PAPER, 96),
])
def test_same_day_retains_items_after_the_window(run_builder, source, kind, hours):
    morning = BUILDER_NOW - timedelta(hours=1)
    event = builder_raw(source, BUILDER_NOW - timedelta(hours=hours, minutes=30), kind=kind)
    event.fetched_at = event.first_seen_at = morning
    first = run_builder(raw_items=[event], clock=morning)
    assert [item["id"] for item in first["items"]] == [event.id]
    second = run_builder(previous=first)
    assert second["date"] == first["date"] == "2026-10-29"
    assert second["items"] == first["items"]
    next_day = run_builder(previous=second, clock=BUILDER_NOW + timedelta(days=1))
    assert next_day["date"] == "2026-10-30"
    assert next_day["items"] == []


def test_previous_items_still_reject_navigation(run_builder):
    old = builder_raw("vendor", BUILDER_NOW - timedelta(hours=1), kind=ItemType.ADVISORY)
    previous = run_builder(processed=[builder_summary(old)])
    previous["items"][0]["source_url"] = "https://beian.miit.gov.cn/"
    output = run_builder(previous=previous)
    assert output["items"] == []


def test_same_day_keeps_prior_items_and_new_entities(run_builder):
    first = run_builder(raw_items=[builder_raw("nvd", BUILDER_NOW - timedelta(hours=1))])
    new = builder_raw("arxiv", BUILDER_NOW, kind=ItemType.PAPER)
    second = run_builder(raw_items=[new], previous=first)
    assert {item["id"] for item in second["items"]} == {first["items"][0]["id"], new.id}


@pytest.mark.parametrize("excerpt", [False, True])
def test_same_id_keeps_evidence_but_uses_current_content(run_builder, excerpt):
    nvd = builder_raw("nvd", BUILDER_NOW - timedelta(hours=2))
    kev = builder_raw("kev", BUILDER_NOW - timedelta(hours=1), RiskSignal(
        kev_listed=True, kev_status="listed", known_exploited=True,
        known_ransomware=True, kev_date_added="2026-10-29", due_date="2026-11-19",
    ), kind=ItemType.KEV)
    ghsa = normalize_ghsa({
        "ghsa_id": "GHSA-2345-6789-cfgh", "cve_id": "CVE-2026-1234",
        "summary": "Source-supported advisory", "description": "Fixed version evidence",
        "published_at": (BUILDER_NOW - timedelta(hours=1)).isoformat(),
        "updated_at": (BUILDER_NOW - timedelta(hours=1)).isoformat(),
        "html_url": "https://github.com/advisories/GHSA-2345-6789-cfgh",
        "vulnerabilities": [{"first_patched_version": "1.2.3"}],
    }, BUILDER_NOW)
    assert ghsa is not None and ghsa.risk.patch_status == "available"
    ghsa.risk.patch_references = [ghsa.source_info.source_url]
    first = run_builder(processed=[builder_summary(item) for item in (nvd, kev, ghsa)])
    before = first["items"][0]
    assert before["id"] == nvd.id
    assert before["risk"]["kev_listed"] is True
    assert before["risk"]["patch_status"] == "available"

    current = nvd.model_copy(deep=True)
    current.title = "Corrected current source title"
    current.summary = "Changed source evidence must not use an old model summary"
    current.updated_at = BUILDER_NOW
    current.source_info.source_name = "Current NVD"
    current.risk.patch_status = "unavailable"
    current.risk.known_ransomware = False
    summary = builder_summary(current, excerpt=excerpt)
    second = run_builder(processed=[summary], previous=first, health={"sources": {
        "nvd": {"status": "success"}, "kev": {"status": "failed"}, "ghsa": {"status": "failed"},
    }})
    assert len(second["items"]) == 1
    after = second["items"][0]
    assert after["id"] == before["id"]
    assert after["title"] == current.title
    assert after["summary"] == current.summary
    assert after["source_name"] == current.source_info.source_name
    assert after["updated_at"] == current.updated_at.isoformat().replace("+00:00", "Z")
    assert after["llm_summary"] == summary.llm_summary.model_dump(mode="json")
    assert after["summary_status"] == ("excerpt" if excerpt else "model")
    assert after["risk"]["kev_listed"] is True
    assert after["risk"]["known_exploited"] is True
    assert after["risk"]["known_ransomware"] is True
    assert after["risk"]["kev_status"] == "listed"
    assert after["risk"]["kev_date_added"] == "2026-10-29"
    assert after["risk"]["due_date"] == "2026-11-19"
    assert after["risk"]["patch_status"] == "available"
    assert after["risk"]["patch_references"] == before["risk"]["patch_references"]
    assert set(after["aliases"]) == set(before["aliases"])
    assert {source["source"] for source in after["related_sources"]} == {"kev", "ghsa"}
    assert second["sections"]["vuln_exploited"] == [after["id"]]
    assert second["sections"]["vuln_baseline"] == []
    assert after["risk_score"] == before["risk_score"]
    assert after["recommendation_score"] == before["recommendation_score"] - (0.4 if excerpt else 0)
    third = run_builder(processed=[summary], previous=second)
    assert third["items"] == second["items"]


@pytest.mark.parametrize("left,right", list(product([None, False, True], repeat=2)))
@pytest.mark.parametrize("reverse", [False, True])
def test_known_ransomware_merges_three_states(left, right, reverse):
    items = [
        builder_summary(builder_raw("nvd", BUILDER_NOW, RiskSignal(known_ransomware=left))),
        builder_summary(builder_raw("kev", BUILDER_NOW, RiskSignal(known_ransomware=right))),
    ]
    snapshots = [item.model_dump(mode="json") for item in items]
    expected = True if True in (left, right) else False if False in (left, right) else None
    merged = m.aggregate_vulnerabilities(items[::-1] if reverse else items)[0]
    assert merged.source == "nvd"
    assert merged.risk.known_ransomware is expected
    assert [item.model_dump(mode="json") for item in items] == snapshots
