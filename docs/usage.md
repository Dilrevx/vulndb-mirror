# Usage

## Quick Start

1. Install dependencies:

```bash
uv sync
uv run playwright install chromium   # aliyun channel only
```

2. Prepare env:

```bash
cp .env.example .env
```

3. Run crawler:

```bash
# Aliyun channel (default)
uv run vulndb-mirror crawl

# Trickest CVE channel
uv run vulndb-mirror crawl --channel trickest_cve
```

---

## Channel: aliyun (default)

Scrapes [avd.aliyun.com](https://avd.aliyun.com) via Playwright.  
Enriched fields: CVSS score/vector, CWE, severity, published/modified dates.

### Crawl incremental raw data

```bash
uv run vulndb-mirror crawl
uv run vulndb-mirror crawl --start-page 50
```

默认 `SYNC_MODE=hybrid`，会执行 `head_incremental`：

1. `head_incremental`：从第 1 页开始按 `SINCE` 做增量抓取（命中旧数据后停止）。
2. `head` 阶段默认会跳过已成功 checkpoint 的中间页（可通过 `HEAD_SKIP_OK_PAGES` 控制），并强制重查前 `HEAD_RECHECK_PAGES` 页。

这会复用已有 `page_checkpoints` 与历史元信息，不需要重跑历史结果。
如果未设置 `SINCE`，会自动回退到上次保存的 `last_seen_date` 作为前段增量阈值。

如果需要保持旧行为（单段线性）：

```bash
SYNC_MODE=linear uv run vulndb-mirror crawl
```

### Show missing/failed page ranges

```bash
uv run vulndb-mirror gaps
```

### Retry specific pages

```bash
uv run vulndb-mirror retry --pages 50 51 52
```

---

## Channel: trickest_cve

从 [trickest/cve](https://github.com/trickest/cve) Git 仓库同步 CVE 数据，**不需要 Playwright**。  
主要字段：description、affected products、PoC references（GitHub 链接列表）。  
数据写入独立目录 `./output/trickest_cve/`，与 aliyun 数据完全隔离。

### First sync（首次运行，clone 仓库 + 全量导入）

```bash
uv run vulndb-mirror crawl --channel trickest_cve
```

首次运行会：
1. `git clone https://github.com/trickest/cve.git` 到 `output/trickest_cve/trickest_repo/`
2. 遍历所有年份目录下的 `CVE-*.md` 文件（约数十万条）
3. 每条解析为 `RawAVDEntry` 存入 storage

### Incremental sync（增量同步）

再次执行同一条命令即为增量模式——自动对比上次同步的 git commit hash，只处理变动文件：

```bash
uv run vulndb-mirror crawl --channel trickest_cve
```

### Force full re-sync（强制全量重导入）

```bash
uv run vulndb-mirror crawl --channel trickest_cve --full
```

### 相关环境变量

```env
TRICKEST_DATA_DIR=./output/trickest_cve   # 数据目录，默认值
GIT_CLONE_VIA_SSH=false                   # true = 使用 git@github.com SSH 协议
GIT_PROXY=socks5://127.0.0.1:1080         # 可选，git 操作走代理（HTTPS channel 有效）
SINCE=2023-01-01                          # 按年份过滤，只导入 >= 该年份的 CVE
```

---

## Start API service

```bash
uv run vulndb-mirror api
```

If port `8787` is already in use:

```bash
RAWDB_API_PORT=8791 uv run vulndb-mirror api
```

Then open:

- `http://127.0.0.1:<RAWDB_API_PORT>/docs` for OpenAPI docs (default port is `8787`)

## Start standalone web UI

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

Web UI: `http://127.0.0.1:3000`

The browser is optimized for vulnerability triage:

- fixed left filter sidebar with summary stats
- inline detail cards in the list
- right-side drawer for full CVE details
- direct hyperlinks for detail / references / patch URLs
- configurable PoC status heuristics shown per CVE
- date filters hidden under advanced options

---

## Minimal Env Keys

```env
# Aliyun channel
MAX_PAGES=200
PAGE_CONCURRENCY=4
SYNC_MODE=hybrid
HEAD_SKIP_OK_PAGES=true
HEAD_RECHECK_PAGES=10
DATA_DIR=./output/aliyun_cve
RAWDB_STORAGE_BACKEND=dual
RAWDB_API_HOST=127.0.0.1
RAWDB_API_PORT=8787
LOG_DIR=./logs

# Trickest channel
TRICKEST_DATA_DIR=./output/trickest_cve
GIT_CLONE_VIA_SSH=false
# GIT_PROXY=socks5://127.0.0.1:1080
```

## Output Locations

### aliyun channel

- Raw files: `output/aliyun_cve/raw/CVE-*.json`
- SQLite DB: `output/aliyun_cve/raw.db`
- Page/meta state: `output/aliyun_cve/.rawdb.state.json`
- Logs: `logs/*-crawler.log`

### trickest_cve channel

- Git repo clone: `output/trickest_cve/trickest_repo/`
- Raw files: `output/trickest_cve/raw/CVE-*.json`
- SQLite DB: `output/trickest_cve/raw.db`
- Sync state (last commit): `output/trickest_cve/.trickest_state.json`

状态文件/数据库中会新增以下同步游标（自动兼容旧状态）：

- `head_last_stop_page`: 上次前段增量停止页（aliyun）
- `last_commit` / `last_sync`: 上次同步 commit hash 与时间（trickest）

---

## GitHub Cache 状态生命周期

`sync` 命令在 CVE 抓取完成后会触发两阶段 GitHub 数据缓存：

1. **Discover** — 从近期更新的 CVE 条目中提取 GitHub repo 引用并入队
2. **Worker** — 按 `(priority ASC, enqueued_at ASC)` 顺序消费队列，抓取 SBOM/languages

### `github_sbom_cache` / `github_languages_cache` 状态流转

| 状态 | 含义 | 触发条件 | `next_batch` 是否挑选 | `enqueue_many` 行为 |
|------|------|----------|----------------------|---------------------|
| `pending` | 等待处理 | 首次发现或 `error`/`fetched` 遇到新 CVE | **是** | 保持 `pending`（不更新 `enqueued_at`） |
| `fetched` | 已成功抓取 | HTTP 200 / 304 | 否 | 有新 CVE → 重置 `pending` 并更新 `enqueued_at`；否则保持不动 |
| `skip_404` | repo 不存在或未开启 SBOM | HTTP 404 | 否 | **永久保持**，不再重试 |
| `skip_403` | private / SBOM 功能禁用 | HTTP 403 | 否 | **永久保持**，不再重试 |
| `error` | 瞬时错误 | HTTP 5xx / 网络异常 / 解析失败 | 否 | 有新 CVE → 重置 `pending` 并更新 `enqueued_at`；否则保持不动 |

### 关键设计要点

- **不重复拉取**：已 `fetched` 的 repo 只在有新 CVE 引用时才会重新检查 BOM 更新（新 CVE 可能意味着依赖发生了变化）
- **优先队列**：`priority=0`（patch URL 来源）始终先于 `priority=1`（reference 来源）处理
- **增量 discover**：sync 循环在第一轮全量扫描后，后续轮次仅扫描增量 CVE 条目（`since_iso`），避免重复入队
- **`enqueued_at` 更新**：repo 因新 CVE 重新入队时 `enqueued_at` 会更新，使其排到同优先级队尾，确保 FIFO 公平性
- **404/403 永久跳过**：这些状态表示 repo 本质不可达，不会浪费 API budget 重试
- **error 可重试**：500/网络异常等瞬时错误，当引用了该 repo 的新 CVE 出现时给予重试机会

### SBOM 与 Languages 的 304 行为差异

GitHub `/languages` 端点返回 `ETag`，支持 `If-None-Match` 条件请求，缓存命中时返回 **304 Not Modified**，不消耗 API quota。

GitHub `/dependency-graph/sbom` 端点**不返回 `ETag`**，每次请求均为完整 **200 OK** 响应，始终消耗 API quota。这是 GitHub API 的平台限制，不影响队列推进正确性，但意味着 SBOM 缓存的刷新会比 languages 慢。
