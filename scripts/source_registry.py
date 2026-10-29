import yaml
import re
from urllib.parse import urlparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

class SourceConfig:
    def __init__(self, data: Dict[str, Any]):
        if not isinstance(data, dict) or any(not isinstance(data.get(k), str) or not data[k].strip()
                                             for k in ("id", "name", "url")):
            raise ValueError("Source requires nonempty id, name and url")
        if not isinstance(data.get("enabled", False), bool):
            raise ValueError(f"{data['id']}: enabled must be boolean")
        if urlparse(data["url"]).scheme not in {"https", "http"}:
            raise ValueError(f"{data['id']}: invalid source URL")
        if data.get("source_quality", "secondary") not in {"primary", "secondary", "community", "unknown"}:
            raise ValueError(f"{data['id']}: invalid source_quality")
        self.id: str = data["id"]
        self.name: str = data["name"]
        self.region: str = data.get("region", "GLOBAL")
        self.category: str = data.get("category", "")
        self.content_type: str = data.get("content_type", "")
        self.source_quality: str = data.get("source_quality", "secondary")
        self.parser: str = data.get("parser", "manual_pending")
        self.url: str = data["url"]
        self.enabled: bool = data.get("enabled", False)
        self.rate_limit_seconds: int = data.get("rate_limit_seconds", 5)
        self.tags: List[str] = data.get("tags", [])
        self.notes: str = data.get("notes", "")
        self.expected_fields: List[str] = data.get("expected_fields", [])
        self.safety_policy: str = data.get("safety_policy", "strict_no_poc")
        self.article_selector: Optional[str] = data.get("article_selector")
        self.article_url_pattern: Optional[str] = data.get("article_url_pattern")
        self.article_container_selector: Optional[str] = data.get("article_container_selector")
        self.article_date_selector: Optional[str] = data.get("article_date_selector")
        self.article_date_heading: Optional[str] = data.get("article_date_heading")
        self.article_title_pattern: Optional[str] = data.get("article_title_pattern")
        self.article_date_field: str = data.get("article_date_field", "published_at")
        if not isinstance(self.article_date_field, str) or self.article_date_field not in {"published_at", "updated_at"}:
            raise ValueError(f"{self.id}: invalid article_date_field")
        if self.article_url_pattern:
            re.compile(self.article_url_pattern)
        if self.article_title_pattern:
            re.compile(self.article_title_pattern)

def load_sources(config_path: Union[str, Path]) -> List[SourceConfig]:
    """加载并解析指定的 YAML 配置文件。"""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
        
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise ValueError("Source configuration must contain a sources array")
    sources = []
    seen = set()
    for s_data in data.get("sources", []):
        source = SourceConfig(s_data)
        if source.id in seen:
            raise ValueError(f"Duplicate source id: {source.id}")
        seen.add(source.id)
        sources.append(source)
        
    return sources

def get_enabled_sources(sources: List[SourceConfig]) -> List[SourceConfig]:
    """获取所有启用的源，过滤掉 manual_pending 的未实现源。"""
    return [s for s in sources if s.enabled and s.parser != "manual_pending"]
