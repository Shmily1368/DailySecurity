import pytest

import rank_items as m
from models import ItemType
from summarize_with_llm import build_digest_item, build_llm_summary
from test_llm import raw_item


@pytest.mark.parametrize("scenario", ["no_patch", "denied_patch", "confirmed_patch"])
def test_patch_evidence(scenario):
    raw = raw_item(kind=ItemType.ADVISORY)
    raw.risk.patch_status = "available" if scenario == "confirmed_patch" else "unknown"
    summary = build_llm_summary(raw, {"summary_zh": "暂无补丁，尚无修复版本", "recommended_action_zh": "关注补丁"})
    item = m.calculate_scores(build_digest_item(raw, summary))
    assert any("有可用补丁" in r for r in item.rank_reasons) == (scenario == "confirmed_patch")


@pytest.mark.parametrize("scenario", ["fallback", "refusal", "model"])
def test_model_bonus(scenario):
    raw = raw_item()
    summary = build_llm_summary(raw, {"novelty_score": 0.8, "actionability_score": 0.8,
                                     "refusal": scenario == "refusal"})
    if scenario == "fallback":
        summary.prompt_version = "fallback"
    item = m.calculate_scores(build_digest_item(raw, summary))
    assert any("LLM 评分" in r for r in item.rank_reasons) == (scenario == "model")


@pytest.mark.parametrize("quality", ["primary", "secondary", "community", "unknown"])
def test_source_quality(quality):
    raw = raw_item(kind=ItemType.ADVISORY)
    raw.source_info.source_quality = quality
    item = m.calculate_scores(build_digest_item(raw, build_llm_summary(raw, {})))
    assert any("官方一手" in r for r in item.rank_reasons) == (quality == "primary")
    assert any(quality.title() in r for r in item.rank_reasons)


def test_rank_priority():
    low = raw_item(1)
    low.risk.cvss_score = 1
    high = raw_item(2)
    items = [build_digest_item(r, build_llm_summary(r, {})) for r in (low, high)]
    assert m.rank_items(items)[0].id == high.id
