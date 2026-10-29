"""Offline contract and pipeline integration checks; no fetch or LLM API calls."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from pydantic import ValidationError

import fetch_arxiv
import run_pipeline
import validate_data
from models import ConfidenceLabel, ItemType, LlmSummary, RawItem
from summarize_with_llm import build_llm_summary, dump_digest_items


ROOT = Path(__file__).resolve().parents[1]


def raw_item(item_type: ItemType = ItemType.CVE) -> RawItem:
    now = datetime.now(timezone.utc)
    return RawItem(
        id=f"fixture:{item_type.value}", type=item_type, title="Offline source fixture",
        summary="Source text used for offline integration verification.",
        source_info={"source": "fixture", "source_name": "Fixture",
                     "source_url": "https://example.com/security", "native_id": item_type.value},
        published_at=now, fetched_at=now,
    )


def check_contracts() -> None:
    schema = json.loads((ROOT / "schemas/digest_item.schema.json").read_text())
    summary_schema = {"$ref": "#/$defs/LlmSummary", "$defs": schema["$defs"]}
    validator = Draft202012Validator(summary_schema)
    allowed = {value for value in schema["$defs"]["LlmSummary"]["properties"]["confidence_label"]["enum"]
               if value is not None}
    assert allowed == {value.value for value in ConfidenceLabel}
    for item_type in ItemType:
        for label in [*allowed, "source_only", "title_only", "insufficient_content",
                      "made_up_label", None]:
            result = build_llm_summary(raw_item(item_type), {
                "summary_zh": "中文摘要。" * 80, "why_it_matters_zh": "离线验证",
                "confidence_label": label, "confidence": "0.7",
            })
            validator.validate(result.model_dump(mode="json"))
            assert len(result.summary_zh) > 120  # 保留既有详尽摘要需求
    for confidence in ["0.9", "single_source", "source_confirmed", "made_up_label", None]:
        result = build_llm_summary(raw_item(), {"confidence": confidence})
        assert result.confidence_label is None or result.confidence_label.value in allowed
        validator.validate(result.model_dump(mode="json"))
    paper = raw_item(ItemType.PAPER)
    result = build_llm_summary(paper, {"confidence_label": "full_text", "confidence": 0.99})
    assert result.confidence_label == "abstract_only" and result.confidence <= 0.5
    paper.summary = ""
    assert build_llm_summary(paper, {}).confidence_label == "metadata_only"
    try:
        LlmSummary(summary_zh="x", why_it_matters_zh="x", novelty_score=0.5,
                   actionability_score=0.5, confidence=0.5, confidence_label="made_up_label")
    except ValidationError:
        pass
    else:
        raise AssertionError("Model accepted an unknown label")
    for item_type, category in [(ItemType.ADVISORY, "advisory"), (ItemType.THREAT_REPORT, "threat-intel")]:
        result = build_llm_summary(raw_item(item_type), {"topics": ["apt"], "confidence": "single_source"})
        assert result.category == category and result.tags == ["apt"]
    print("[OK] Summary labels, numeric confidence, categories and paper evidence constraints")


def check_validation() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        empty = root / "empty_digest.json"
        dump_digest_items([], empty)
        assert validate_data.validate_file(empty)[0]
        malformed = root / "malformed_digest.json"
        malformed.write_text('{"kind":"digest_items","items":"invalid"}')
        assert not validate_data.validate_file(malformed)[0]
        invalid = root / "invalid_daily.json"
        invalid.write_text(json.dumps({"date": "invalid", "hero": {},
                                      "items": [{"llm_summary": {}}]}))
        ok, errors = validate_data.validate_file(invalid)
        assert not ok and any("hero" in e for e in errors)
        diagnostic = root / "vendor_errors.json"
        diagnostic.write_text('[{"source_id": "fixture", "error": "timeout"}]')
        business = root / "error_related_items.json"
        business.write_text('{"items": []}')
        with patch.object(validate_data, "DEFAULT_DIRS", [root]):
            files = validate_data._collect_all_files()
            assert diagnostic not in files and business in files
        assert not validate_data.validate_file(diagnostic)[0]
    print("[OK] Empty intermediate output, complete digest validation and diagnostic filtering")


def check_pipeline(case: str) -> None:
    with tempfile.TemporaryDirectory(prefix="pipeline-check-") as directory:
        root = Path(directory)
        (root / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
        for name in ("raw", "processed", "daily", "state"):
            (root / "data" / name).mkdir(parents=True)
        old_latest = root / "data/daily/latest.json"
        old_latest.write_text('{"previous": "published digest"}')
        (root / "data/daily/index.json").write_text('{"latest":"2020-01-01","dates":["2020-01-01"]}')
        # 最新时间戳的旧摘要也必须排除，不能只依赖时间窗口。
        stale = root / "data/processed/daily_digest.json"
        from summarize_with_llm import build_digest_item
        old_item = raw_item()
        old_item.id = "stale:previous-run"
        dump_digest_items([build_digest_item(old_item, build_llm_summary(old_item, {}))], stale)
        state = root / "data/state/dblp_state.json"
        state.write_text('{"seen_keys": ["existing"]}')
        reports, work = root / "reports", root / "work"
        reports.mkdir()
        work.mkdir()
        commands = []
        original_run = run_pipeline.run_command

        def simulate(name, args, reports, statuses, *, timeout, env):
            commands.append(name)
            if name == "build-digest":
                # 构建使用真实脚本；关闭 Top 10 的外部 API，确保本检查完全离线。
                offline_env = {**env, "OPENAI_API_KEY": ""}
                return original_run(name, args, reports, statuses, timeout=timeout, env=offline_env)
            output = Path(args[args.index("--output") + 1])
            if name.startswith("summarize-"):
                if case == "explicit_mock":
                    return original_run(name, args, reports, statuses, timeout=timeout, env=env)
                # 故障前遗留的无效输出应丢弃。
                output.write_text('{"items":[{"id":"partial:failed-summary"}]}')
                statuses.append({"name": name, "status": "failed"})
                return False
            if name == "fetch-conferences":
                new_state = Path(args[args.index("--state-file") + 1])
                new_state.write_text('{"seen_keys":["new-state"]}')
            if name == "fetch-nvd" and case != "all_sources_fail":
                payload = {"items": [raw_item().model_dump(mode="json")]}
                if case == "invalid_source":
                    payload["items"][0]["type"] = "unknown"
                output.write_text(json.dumps(payload))
                statuses.append({"name": name, "status": "success"})
                return True
            if name == "fetch-vendor":
                output.with_name(f"{output.stem}_errors.json").write_text('[{"error":"fixture timeout"}]')
            output.write_text('{"items":[{"id":"partial:failed-fetch"}]}')
            statuses.append({"name": name, "status": "timeout"})
            return False

        env = {"OPENAI_API_KEY": "offline-fixture"} if case == "summaries_fail" else {}
        with patch.object(run_pipeline, "PROJECT_ROOT", root), \
             patch.object(run_pipeline, "run_command", simulate), \
             patch.dict(os.environ, env, clear=True):
            statuses = []
            success = run_pipeline.run_pipeline(work, reports, statuses, mock=case == "explicit_mock",
                                               source_timeout=5, llm_timeout=20)
        assert len([name for name in commands if name.startswith("fetch-")]) == 9
        assert (reports / "vendor_advisories_errors.json").exists()
        # 已失败的会议来源不能推进去重状态，即使其他来源成功发布。
        assert json.loads(state.read_text()) == {"seen_keys": ["existing"]}
        if case in {"all_sources_fail", "invalid_source"}:
            assert not success
            assert json.loads(old_latest.read_text()) == {"previous": "published digest"}
            assert stale.exists()
            assert json.loads(state.read_text()) == {"seen_keys": ["existing"]}
        else:
            assert success
            digest = json.loads(old_latest.read_text())
            assert [x["id"] for x in digest["items"]] == ["fixture:cve"]
            assert digest["is_mock"] is (case == "explicit_mock")
            if case == "explicit_mock":
                assert "[MOCK]" in digest["items"][0]["llm_summary"]["summary_zh"]
            else:
                assert digest["items"][0]["llm_summary"]["prompt_version"] == "fallback"
                assert "[MOCK]" not in digest["items"][0]["llm_summary"]["summary_zh"]
            if case == "explicit_mock":
                assert [x["id"] for x in json.loads(stale.read_text())["items"]] == ["fixture:cve"]
            else:
                assert not stale.exists()
            assert validate_data.validate_file(old_latest)[0]
            assert "2020-01-01" in json.loads((root / "data/daily/index.json").read_text())["dates"]
    print(f"[OK] Pipeline integration: {case}")


def main() -> int:
    check_contracts()
    check_validation()
    for case in ("one_source_survives", "summaries_fail", "all_sources_fail", "invalid_source", "explicit_mock"):
        check_pipeline(case)
    # 重试分类验证不发送请求。
    import httpx
    request = httpx.Request("GET", "https://example.com")
    for status, expected in [(429, True), (503, True), (404, False), (401, False)]:
        error = httpx.HTTPStatusError("fixture", request=request, response=httpx.Response(status))
        assert fetch_arxiv._retryable(error) is expected
    print("[OK] All offline checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
