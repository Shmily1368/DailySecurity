import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

class SourceConfig:
    def __init__(self, data: Dict[str, Any]):
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

def load_sources(config_path: Union[str, Path]) -> List[SourceConfig]:
    """加载并解析指定的 YAML 配置文件。"""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
        
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        
    sources = []
    for s_data in data.get("sources", []):
        sources.append(SourceConfig(s_data))
        
    return sources

def get_enabled_sources(sources: List[SourceConfig]) -> List[SourceConfig]:
    """获取所有启用的源，过滤掉 manual_pending 的未实现源。"""
    return [s for s in sources if s.enabled and s.parser != "manual_pending"]
