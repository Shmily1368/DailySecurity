import pytest

import source_registry as m


@pytest.mark.parametrize("case", ["normal", "missing", "duplicates", "invalid_enabled", "invalid_root"])
def test_source_loading(tmp_path, case):
    config = tmp_path / "sources.yml"
    if case == "missing":
        with pytest.raises(FileNotFoundError):
            m.load_sources(config)
        return
    entry = {"id": "fixture", "name": "Fixture", "url": "https://example.org/security",
             "enabled": True, "parser": "html", "article_selector": ".security-list a[href]",
             "article_url_pattern": r"/security/\d+"}
    import yaml
    data = {"sources": [entry]}
    if case == "duplicates":
        data["sources"].append(entry.copy())
    if case == "invalid_enabled":
        entry["enabled"] = "false"
    if case == "invalid_root":
        data = ["wrong"]
    config.write_text(yaml.safe_dump(data))
    if case != "normal":
        with pytest.raises(ValueError):
            m.load_sources(config)
        return
    sources = m.load_sources(config)
    assert len(m.get_enabled_sources(sources)) == 1
    assert sources[0].article_selector == entry["article_selector"]
    assert sources[0].article_url_pattern == entry["article_url_pattern"]
    pending = m.SourceConfig({**entry, "id": "pending", "parser": "manual_pending"})
    disabled = m.SourceConfig({**entry, "id": "disabled", "enabled": False})
    assert m.get_enabled_sources([sources[0], pending, disabled]) == [sources[0]]


@pytest.mark.parametrize("field", ["published_at", "updated_at", "invalid", None, 42, [], {}])
def test_article_date_semantics(field):
    entry = {"id": "fixture", "name": "Fixture", "url": "https://example.org",
             "article_date_field": field}
    if not isinstance(field, str) or field not in {"published_at", "updated_at"}:
        with pytest.raises(ValueError, match="article_date_field"):
            m.SourceConfig(entry)
    else:
        assert m.SourceConfig(entry).article_date_field == field
    assert m.SourceConfig({k: v for k, v in entry.items() if k != "article_date_field"}).article_date_field == "published_at"
