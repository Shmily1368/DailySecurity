import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

import fetch_top_conferences as m


@pytest.mark.parametrize("scenario", ["match_second", "mismatch", "empty", "failure"])
def test_openalex_identity(scenario):
    candidates = [{"title": "Different study", "abstract_inverted_index": {"Wrong": [0]}}]
    if scenario == "match_second":
        candidates.append({"title": "Target study.", "id": "https://openalex.org/W42",
                           "abstract_inverted_index": {"Correct": [0], "abstract": [1]}})
    if scenario == "empty":
        candidates = []
    res = httpx.Response(200, json={"results": candidates})
    getter = AsyncMock(return_value=res, side_effect=RuntimeError("Unavailable") if scenario == "failure" else None)
    with patch.object(m, "_safe_get_async", getter):
        value = asyncio.run(m.fetch_abstract_openalex_async(None, "Target study", asyncio.Semaphore(1)))
    assert value == ("Correct abstract" if scenario == "match_second" else "")


@pytest.mark.parametrize("year", ["2021", "2026", ""])
def test_format_dates(year):
    now = datetime(2026, 10, 29, tzinfo=timezone.utc)
    item = m.format_item({"key": "conf/sp/42", "title": "Target study", "year": year},
                        "ieee_sp", {"name": "IEEE S&P", "url": "https://example.org/"}, now)
    assert item["published_at"] is None
    assert item["date_precision"] == ("year" if year else "unknown")
    assert item["published_year"] == (int(year) if year else None)
    assert item["fetched_at"] == now.isoformat()


@pytest.mark.parametrize("scenario", ["already_seen", "new_paper"])
def test_incremental_run(tmp_path, monkeypatch, scenario):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"seen_keys": ["conf/sp/42"] if scenario == "already_seen" else []}))
    output = tmp_path / "papers.json"
    monkeypatch.setattr("sys.argv", ["fetch", "--output", str(output), "--state-file", str(state)])
    paper = {"key": "conf/sp/42", "title": "Target study", "year": "2026"}
    fallback = Mock(return_value=[])
    async def processed(papers, source_id, info, now):
        return [m.format_item(paper, source_id, info, now) for paper in papers]
    with patch.object(m, "fetch_dblp_all", return_value=[paper]), \
         patch.object(m, "fetch_dblp_random", fallback), \
         patch.object(m, "process_papers_async", side_effect=processed):
        m.run()
    assert len(json.loads(output.read_text())) == (0 if scenario == "already_seen" else 1)
    fallback.assert_not_called()


def conference_args(tmp_path, monkeypatch, limit=5, force=False):
    output, state = tmp_path / "papers.json", tmp_path / "state.json"
    args = ["fetch", "--output", str(output), "--state-file", str(state),
            "--limit-per-conf", str(limit)]
    if force:
        args.append("--force")
    monkeypatch.setattr("sys.argv", args)
    return output, state


async def format_processed(papers, source_id, info, now):
    return [m.format_item(paper, source_id, info, now) for paper in papers]


@pytest.mark.parametrize("force", [False, True])
def test_backlog_bounded_every_run_with_truthful_seen(tmp_path, monkeypatch, force):
    output, state = conference_args(tmp_path, monkeypatch)
    batches = []

    def fetcher(stream, year):
        if stream != "conf/sp":
            return []
        count = 700 if year == datetime.now().year else 600
        return [{"key": f"{stream}/{year}/{index}", "title": f"Paper {year}-{index}",
                 "year": str(year)} for index in range(count)]

    async def processed(papers, source_id, info, now):
        batches.append(len(papers))
        return await format_processed(papers, source_id, info, now)

    with patch.object(m, "fetch_dblp_all", side_effect=fetcher), \
         patch.object(m, "process_papers_async", side_effect=processed):
        m.run()
        first_items = json.loads(output.read_text())
        first_seen = json.loads(state.read_text())["seen_keys"]
        assert len(first_items) == len(first_seen) == 5
        if force:
            conference_args(tmp_path, monkeypatch, force=True)
        m.run()

    second_items = json.loads(output.read_text())
    second_seen = json.loads(state.read_text())["seen_keys"]
    assert batches == [5, 5]
    assert len(second_items) == 5
    assert len(second_seen) == (5 if force else 10)
    assert {item["source_info"]["native_id"] for item in first_items + second_items} == {
        key.replace("/", "_") for key in second_seen
    }
    if not force:
        assert {item["id"] for item in first_items}.isdisjoint(
            item["id"] for item in second_items
        )


@pytest.mark.parametrize("failed_years", ["current", "previous", "both"])
def test_year_failures_preserve_successful_year_and_health(tmp_path, monkeypatch, failed_years):
    output, state = conference_args(tmp_path, monkeypatch)
    current = datetime.now().year
    years = {"current": {current}, "previous": {current - 1},
             "both": {current, current - 1}}[failed_years]

    def fetcher(stream, year):
        if year in years:
            raise httpx.ReadTimeout(f"{year} unavailable")
        return [{"key": f"{stream}/{year}/42", "title": f"Paper {year}", "year": str(year)}]

    with patch.object(m, "fetch_dblp_all", side_effect=fetcher), \
         patch.object(m, "process_papers_async", side_effect=format_processed):
        m.run()
    items = json.loads(output.read_text())
    statuses = json.loads(output.with_name("papers_status.json").read_text())
    seen = json.loads(state.read_text())["seen_keys"]
    assert len(items) == len(seen) == (0 if failed_years == "both" else 4)
    assert {row["status"] for row in statuses} == {
        "failed" if failed_years == "both" else "partial"
    }
    for row in statuses:
        assert set(row["failed_years"]) == years
        assert {error["year"] for error in row["errors"]} == years
        assert all(error["error_type"] == "ReadTimeout" for error in row["errors"])
        assert row["item_count"] == (0 if failed_years == "both" else 1)
    from run_pipeline import source_status
    status, _, usable = source_status(output, True)
    assert status == ("failed" if failed_years == "both" else "partial")
    assert usable == (failed_years != "both")


def test_successful_empty_year_with_other_year_failure_is_partial(tmp_path, monkeypatch):
    output, state = conference_args(tmp_path, monkeypatch)

    def fetcher(stream, year):
        if year < datetime.now().year:
            raise httpx.ReadTimeout("Previous year unavailable")
        return []

    with patch.object(m, "fetch_dblp_all", side_effect=fetcher):
        m.run()
    assert json.loads(output.read_text()) == []
    assert json.loads(state.read_text())["seen_keys"] == []
    assert all(row["status"] == "partial" for row in json.loads(
        output.with_name("papers_status.json").read_text()
    ))


def test_seen_only_tracks_emitted_papers(tmp_path, monkeypatch):
    output, state = conference_args(tmp_path, monkeypatch)
    papers = [{"key": f"conf/sp/{index}", "title": f"Paper {index}", "year": "2026"}
              for index in range(2)]

    async def processed(batch, source_id, info, now):
        return await format_processed(batch[:1], source_id, info, now)

    with patch.object(m, "fetch_dblp_all", side_effect=lambda stream, year:
                      papers if stream == "conf/sp" else []), \
         patch.object(m, "process_papers_async", side_effect=processed):
        m.run()
    assert len(json.loads(output.read_text())) == 1
    assert json.loads(state.read_text())["seen_keys"] == ["conf/sp/0"]


@pytest.mark.parametrize("limit", [0, -1])
def test_invalid_per_run_limit_rejected(tmp_path, monkeypatch, limit):
    conference_args(tmp_path, monkeypatch, limit=limit)
    with patch.object(m, "fetch_dblp_all") as fetcher:
        with pytest.raises(SystemExit) as exc:
            m.run()
    assert exc.value.code == 2
    fetcher.assert_not_called()


def test_real_dblp_and_abstract_processing_drains_only_emitted_batches(tmp_path, monkeypatch):
    output, state = conference_args(tmp_path, monkeypatch)
    current = datetime.now(timezone.utc).year

    def dblp(url, **kwargs):
        query = parse_qs(urlparse(url).query)["q"][0]
        hits = []
        if "stream:conf/sp:" in query:
            year = current if f"year:{current}:" in query else current - 1
            hits = [{"info": {"key": f"conf/sp/{year}/{index}", "title": f"Study {year} {index}",
                             "type": "Conference and Workshop Papers", "year": str(year)}}
                    for index in range(6)]
        return httpx.Response(200, json={"result": {"hits": {"hit": hits}}})

    async def openalex(client, url, **kwargs):
        title = parse_qs(urlparse(url).query)["filter"][0].removeprefix("title.search:")
        return httpx.Response(200, json={"results": [{
            "id": "https://openalex.org/W42", "title": title,
            "publication_year": int(title.split()[1]),
            "abstract_inverted_index": {"Real": [0], "abstract": [1]},
        }]})

    all_items = []
    with patch.object(m, "_safe_get", side_effect=dblp), \
         patch.object(m, "_safe_get_async", side_effect=openalex) as abstracts:
        for expected in (5, 5, 2, 0):
            before = abstracts.call_count
            m.run()
            items = json.loads(output.read_text())
            assert len(items) == abstracts.call_count - before == expected
            all_items.extend(items)
            assert len(json.loads(state.read_text())["seen_keys"]) == len(all_items)
            assert len({item["id"] for item in all_items}) == len(all_items)
    assert len(all_items) == 12
    assert all(item["summary"] == "Real abstract" and item["abstract_source"]
               == "https://openalex.org/W42" for item in all_items)
    assert all(item["published_at"] is None and item["date_precision"] == "year"
               for item in all_items)
    assert all(row["status"] == "no_new" for row in json.loads(
        output.with_name("papers_status.json").read_text()
    ))


def test_processing_failure_does_not_mark_unemitted_papers_seen(tmp_path, monkeypatch):
    output, state = conference_args(tmp_path, monkeypatch)
    papers = [{"key": "conf/sp/42", "title": "Target study", "year": "2026"}]
    with patch.object(m, "fetch_dblp_all", side_effect=lambda stream, year:
                      papers if stream == "conf/sp" else []), \
         patch.object(m, "process_papers_async", side_effect=RuntimeError("Formatting failed")):
        m.run()
    assert json.loads(output.read_text()) == []
    assert json.loads(state.read_text())["seen_keys"] == []
    statuses = json.loads(output.with_name("papers_status.json").read_text())
    assert statuses[0]["status"] == "failed"
    assert statuses[0]["errors"] == [{"phase": "processing", "error_type": "RuntimeError"}]
