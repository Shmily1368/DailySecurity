from datetime import datetime, timezone

import pytest

import fetch_cisa_kev as m


def entry():
    return {"cveID": "CVE-2026-1234", "dateAdded": "2026-10-29", "dueDate": "2026-11-01",
            "shortDescription": "An exploited vulnerability", "vendorProject": "Fixture",
            "product": "Software", "knownRansomwareCampaignUse": "Known"}


@pytest.mark.parametrize("case", ["normal", "missing_id", "missing_date", "bad_date"])
def test_kev_evidence(case):
    data = entry()
    if case == "missing_id":
        data.pop("cveID")
    elif case == "missing_date":
        data.pop("dateAdded")
    elif case == "bad_date":
        data["dateAdded"] = "not-a-date"
    item = m.entry_to_raw_item(data, datetime.now(timezone.utc))
    if case == "missing_id":
        assert item is None
        return
    assert item.risk.kev_listed and item.risk.known_exploited
    assert item.risk.exploit_maturity == "in_the_wild"
    assert not item.risk.has_public_exploit
    assert item.risk.exploit_references == []
    assert item.source_info.source_quality == "primary"
    if case in {"missing_date", "bad_date"}:
        assert item.published_at is None
        assert item.risk.kev_date_added is None
    else:
        assert item.published_at.strftime("%Y-%m-%d") == "2026-10-29"


@pytest.mark.parametrize("feed", [{}, {"error": "unavailable"}, {"vulnerabilities": None},
                                 {"vulnerabilities": {}}, {"vulnerabilities": []},
                                 {"vulnerabilities": [None, {}, entry()]}])
def test_feed_contract(feed):
    now = datetime.now(timezone.utc)
    if not isinstance(feed.get("vulnerabilities"), list):
        with pytest.raises(m.KevFetchError):
            m.normalize_feed(feed, now)
    else:
        result = m.normalize_feed(feed, now)
        assert len(result) == (1 if feed["vulnerabilities"] else 0)
