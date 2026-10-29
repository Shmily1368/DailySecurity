# 构建与数据管线可靠性

## 网站构建

`src/src/lib/data.ts` 在一次构建中只聚合一次历史日报，再建立「主题 → 有序条目」索引。主题页直接查询索引，避免每生成一页都读取、去重并排序全部历史数据。

索引按原始主题建立，同一条目同一主题只出现一次；条目去重规则、排序及主题 URL 保持原有行为。缓存适用于静态构建中的固定数据快照。开发时修改数据后需要重启开发服务。

部署工作流使用 Node 20 和 npm 缓存，构建步骤所在 job 的上限为 20 分钟。超时会报错，避免再次占满 GitHub Actions 的 6 小时上限。

## 每日数据更新

```bash
python scripts/run_pipeline.py
```

脚本在新的临时目录中逐来源执行采集，每个来源默认最多运行 600 秒。非零退出、超时或业务校验失败的来源会记录状态，仅该来源使用空结果，其余来源继续运行。

只使用本次采集与摘要的文件，不读取上次留下的 `data/raw` 或 `data/processed` 产物。DBLP 去重状态单独复用，只有日报成功发布后才保存新状态。

有 `OPENAI_API_KEY` 时生成真实摘要；单组摘要失败或超时后，仍可用本次原始数据生成明确标注的「原文摘录」。没有 key 时也使用原文摘录，生产流程不会自动改成 mock。Top 10 只补录带 `prompt_version="fallback"` 的摘要，不重复处理已经生成的元数据摘要。

新日报须通过 Pydantic 与 JSON Schema 校验才覆盖已发布数据。如果没有任何符合时间窗口的新条目，管线返回非零退出码，保留上一份日报。部分来源失败且其余来源仍有可用数据时，可以成功发布，但来源异常会出现在 Actions 摘要和诊断文件中。

```bash
# 只用于明确需要模拟数据的开发场景，产出 is_mock=true
python scripts/run_pipeline.py --mock

# 修改单来源或单组摘要的超时秒数
python scripts/run_pipeline.py --source-timeout 600 --llm-timeout 600
```

## 校验与诊断

`data/tmp/pipeline/status.json` 记录各步骤的结果，同目录保存采集与摘要日志。厂商和情报来源的 `*_errors.json` 也会保存到诊断目录。工作流无论成功或失败都会上传该目录为 artifact，保留 14 天；该目录不进入 Git。

`validate_data.py --all` 只排除 `index.json` 和明确命名的 `*_errors.json`，不会因为文件名含有「error」而跳过其他业务 JSON。指定诊断文件进行业务校验仍会失败。

摘要中间文件增加 `kind="digest_items"`，空条目列表也能识别为摘要产物。含有 `hero` 的完整日报必须校验整个日报，不能只校验其中条目。

```bash
# 不访问来源网站，不调用 LLM API
python scripts/check_pipeline.py

# 真实历史数据的静态站点构建
cd src
npm ci
npm run build
```
