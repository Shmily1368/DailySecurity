import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest

import fetch_osv as m


@pytest.mark.parametrize("status", [200, 404, 503])
def test_query_result(status):
    request = httpx.Request("GET", "https://example.org/")
    response = httpx.Response(status, request=request)
    getter = AsyncMock(return_value={"id": "GHSA-test"})
    if status != 200:
        getter.side_effect = httpx.HTTPStatusError("Fixture", request=request, response=response)
    with patch.object(m, "_async_http_get_json", getter):
        if status == 503:
            with pytest.raises(m.OsvFetchError):
                asyncio.run(m.async_fetch_osv(None, "CVE-2026-1234", asyncio.Semaphore(1)))
        else:
            oid, result = asyncio.run(m.async_fetch_osv(None, "CVE-2026-1234", asyncio.Semaphore(1)))
            assert result == ({"id": "GHSA-test"} if status == 200 else 404)


@pytest.mark.parametrize("scenario", ["mixed", "not_found", "failed"])
def test_batch_health(scenario):
    async def query(client, oid, sem):
        if scenario == "not_found":
            return oid, 404
        if oid == "bad" or scenario == "failed":
            raise m.OsvFetchError("HTTP503")
        return oid, {"id": "GHSA-good"}
    with patch.object(m, "async_fetch_osv", side_effect=query):
        try:
            result = asyncio.run(m.fetch_all_osv(["good", "bad"]))
        except m.OsvFetchError:
            assert scenario == "failed"
            return
    assert result.meta["status"] == {"mixed": "partial", "not_found": "not_found", "failed": "failed"}[scenario]
    assert len(result) == (1 if scenario == "mixed" else 0)


def test_normalize_record():
    item = m.entry_to_raw_item({
        "id": "GHSA-test", "aliases": ["CVE-2026-1234"],
        "published": "2026-10-29T00:00:00Z", "summary": "Source vulnerability",
        "affected": [{"package": {"name": "pkg", "ecosystem": "npm"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2"}]}]}],
    }, datetime.now(timezone.utc))
    assert item.cves == ["CVE-2026-1234"]
    assert item.products == ["pkg"]


@pytest.mark.parametrize("queries", [
    ["CVE-2026-1234", "CVE-2026-1235"],
    ["CVE-2026-1234", "GHSA-shared"],
])
def test_duplicate_alias_queries_are_healthy(queries):
    record = {"id": "GHSA-shared", "aliases": ["CVE-2026-1234", "CVE-2026-1235"]}

    async def query(client, oid, sem):
        return oid, dict(record)

    with patch.object(m, "async_fetch_osv", side_effect=query):
        batch = asyncio.run(m.fetch_all_osv(queries))
    assert list(batch) == [record]
    assert batch.meta == {"status": "success", "errors": [], "query_count": 2,
                          "not_found_count": 0}


@pytest.mark.parametrize("bad", [{}, {"id": ""}, {"id": " "}, {"id": None}, {"id": 42}, []])
def test_duplicates_do_not_hide_invalid_responses(bad):
    async def query(client, oid, sem):
        return oid, bad if oid == "bad" else {"id": "GHSA-shared"}

    with patch.object(m, "async_fetch_osv", side_effect=query):
        batch = asyncio.run(m.fetch_all_osv(["first", "duplicate", "bad"]))
    assert len(batch) == 1
    assert batch.meta["status"] == "partial"
    assert batch.meta["errors"] == [{"id": "bad", "error_type": "invalid_response"}]


def test_duplicate_cli_output_preserves_healthy_pipeline_status(tmp_path, monkeypatch):
    import json
    from run_pipeline import source_status

    output = tmp_path / "osv.json"
    monkeypatch.setattr("sys.argv", ["osv", "--cve", "CVE-2026-1234",
                                   "--osv-id", "GHSA-shared", "--output", str(output)])

    async def query(client, oid, sem):
        return oid, {"id": "GHSA-shared", "aliases": ["CVE-2026-1234"]}

    with patch.object(m, "async_fetch_osv", side_effect=query):
        assert m.main() == 0
    payload = json.loads(output.read_text())
    assert len(payload["items"]) == 1
    assert payload["meta"]["errors"] == []
    assert source_status(output, True)[0::2] == ("success", True)
