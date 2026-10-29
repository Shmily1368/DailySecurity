import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Unit tests must not connect to external services")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


@pytest.fixture
def source():
    from source_registry import SourceConfig
    return SourceConfig({
        "id": "fixture", "name": "Fixture Source",
        "url": "https://example.org/security/",
        "source_quality": "secondary", "tags": ["security"],
        "parser": "rss", "enabled": True,
    })
