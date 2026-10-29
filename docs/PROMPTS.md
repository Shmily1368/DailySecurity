# Cyber Security Daily Radar — LLM Prompts

当前版本：`PROMPT_VERSION = "v2"`。实际发送的 system prompt 和各类型模板以 [`scripts/summarize_with_llm.py`](../scripts/summarize_with_llm.py) 中的 `SYSTEM_PROMPT`、`PROMPT_BY_TYPE` 为准，本文记录其数据契约和处理规则。

## 生成原则

- 输出单个 JSON 对象，使用 `LlmSummary` 的字段名。
- 正文使用简体中文，面向防御者提供风险摘要、检测信号和防御建议。
- 仅总结输入证据，不为凑字数编造背景、实验结论、受影响资产或攻击者归因。
- 不输出 PoC 正文、payload、shellcode、攻击步骤或绕过方法。
- 只有来源字段明确标注 KEV、`known_exploited` 或 `exploit_in_the_wild` 时，才可声称已在野利用。
- `summary_zh` 目标为 300~500 字；输入信息不足时可更短并说明限制。不设会破坏历史数据兼容性的硬长度上限。
- `why_it_matters_zh` 提示约束为不超过 150 字。
- 论文仅提供摘要时，程序强制 `abstract_only`，置信度最多 0.5；没有摘要时标注 `metadata_only`。
- 提供来源链接不代表已阅读全文，不能据此标注 `full_text`。

## 统一字段

厂商公告与威胁情报模板也使用 `why_it_matters_zh`、`recommended_action_zh`、`tags`、数字 `confidence`，避免要求模型输出另一套字段名。

| 字段 | 规则 |
| --- | --- |
| `summary_zh` | 非空中文摘要 |
| `why_it_matters_zh` | 非空推荐理由 |
| `impact_zh` | 影响面，可为 null |
| `detection_signals_zh` / `defense_advice_zh` | 字符串数组 |
| `recommended_action_zh` | 防御性行动，可为 null |
| `tags` | 字符串数组 |
| `category` | `vuln`、`exploited`、`research`、`advisory`、`threat-intel`、`detection` |
| `severity_hint` | `critical`、`high`、`medium`、`low`、`info` |
| `novelty_score` / `actionability_score` / `confidence` | 0~1 的数字 |
| `confidence_label` | 下表之一，或 null |
| `refusal` / `refusal_reason` | 拒绝标志与原因 |
| `prompt_version` | 程序注入的版本 |

`affected_assets`、`cves`、`limitations`、威胁组织、恶意软件家族、行业、地区、ATT&CK 技术和 `iocs_present` 等可选字段以 Pydantic 模型及 JSON Schema 为准。不得编造来源未提供的归因或技术 ID。

## 置信度

| 标签 | 未提供数字时的默认置信度 |
| --- | --- |
| `abstract_only` | 0.50 |
| `metadata_only` | 0.55 |
| `with_references` | 0.70 |
| `full_text` | 0.85 |
| `source_confirmed` | 0.90 |
| `single_source` | 0.60 |
| `multi_source` | 0.80 |
| `unverified` | 0.30 |

兼容转换只作用于新生成的摘要：

- `source_only` → `single_source`
- `title_only` → `metadata_only`
- `insufficient_content` → `unverified`
- 未识别标签 → `unverified`，置信度最多 0.3
- `"0.7"` 等数字字符串 → 数字，不复制到标签字段
- 旧版的 `confidence="single_source"` 等来源标签 → 数字与合法标签
- 旧版 `why_it_matters`、`recommended_action`、`topics` → 对应标准字段

持久化模型本身使用明确枚举，不接受未知标签；JSON Schema 使用同一组值。单条输出解析或校验失败时记录警告并跳过，其原始数据仍可生成有标记的原文摘录。完整日报须通过两套校验后才发布。

## Mock 与生产降级

`--mock` 使用本地确定性规则，不调用 API，摘要带 `[MOCK]`。这是显式开发模式，每日管线只有用户手动指定时才启用，并在日报设置 `is_mock=true`。

生产没有 API key 或摘要失败时，使用本次原始数据的摘录，说明「未生成 LLM 摘要」，并标记 `prompt_version="fallback"`。Top 10 只补录这种摘录，不把所有 `metadata_only` 摘要再次提交给模型。

```bash
python scripts/summarize_with_llm.py \
  --input data/raw/mock_items.json \
  --output data/processed/digest_items.json \
  --mock

python scripts/check_pipeline.py
```

更多运行与来源故障处理规则见 [PIPELINE_RELIABILITY.md](./PIPELINE_RELIABILITY.md)。
