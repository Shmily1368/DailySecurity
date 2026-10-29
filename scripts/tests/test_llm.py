from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

import summarize_with_llm as m
from models import ItemType, RawItem, RiskSignal, SourceInfo


def raw_item(index=0, kind=ItemType.CVE):
    return RawItem(
        id=f"nvd:CVE-2026-{1234 + index}", type=kind, title=f"Evidence {index}",
        source_info=SourceInfo(source="vendor", source_sub="secondary",
                               source_quality="secondary", source_name="Secondary Source",
                               source_url=f"https://example.org/article/{index}", native_id=str(index)),
        summary="Source description", published_at=datetime.now(timezone.utc),
        fetched_at=datetime.now(timezone.utc), cves=[f"CVE-2026-{1234 + index}"],
        risk=RiskSignal(cvss_score=9.8),
    )


@pytest.mark.parametrize("hint", ["info", "low", "high"])
def test_source_severity(hint):
    item = raw_item()
    summary = m.build_llm_summary(item, {"severity_hint": hint, "prompt_version": "fallback"})
    assert m.build_digest_item(item, summary).severity.value == "critical"


@pytest.mark.parametrize("endpoint", [None, "", "   ", "https://example.org/v1"])
def test_optional_endpoint(monkeypatch, endpoint):
    if endpoint is not None:
        monkeypatch.setenv("LLM_BASE_URL", endpoint)
    else:
        monkeypatch.delenv("LLM_BASE_URL", raising=False)
    client = m.OpenAiLlmClient("fixture-key")
    assert str(client._client.base_url) == ("https://example.org/v1/" if endpoint and endpoint.strip() else "https://api.openai.com/v1/")
    client._client.close()


@pytest.mark.parametrize("kind", list(ItemType))
def test_prompt_source_quality(kind):
    assert "secondary" in m.render_user_prompt(raw_item(kind=kind))


@pytest.mark.parametrize("scenario", ["success", "refusal", "account_failure", "malformed"])
def test_summary_outcomes(scenario):
    client = Mock(spec=m.LlmClient, name="fixture")
    client.name = "fixture"
    client.summarize.return_value = {"summary_zh": "模型基于来源生成的摘要", "why_it_matters_zh": "理由",
                                    "refusal": scenario == "refusal"}
    if scenario == "account_failure":
        error = RuntimeError("Fixture balance exhausted")
        error.status_code = 402
        client.summarize.side_effect = error
    if scenario == "malformed":
        client.summarize.return_value = []
    items = m.summarize_all([raw_item(i) for i in range(4)], client)
    assert len(items) == (4 if scenario == "success" else 0)
    if scenario == "account_failure":
        assert client.summarize.call_count == 1


def test_summary_cache(tmp_path):
    client = Mock(spec=m.LlmClient)
    client.name = "fixture"
    client.model = "fixture-model"
    client.summarize.return_value = {"summary_zh": "有效摘要", "why_it_matters_zh": "理由"}
    item = raw_item()
    cache = tmp_path / "cache.json"
    first = m.summarize_all([item], client, cache_path=cache)
    second = m.summarize_all([item.model_copy(update={"fetched_at": datetime.now(timezone.utc)})], client, cache_path=cache)
    assert first[0].llm_summary == second[0].llm_summary
    assert client.summarize.call_count == 1
