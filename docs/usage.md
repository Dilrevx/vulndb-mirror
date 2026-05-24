# 使用说明

## 快速开始

1. 安装依赖：

```bash
uv sync
uv run playwright install chromium   # 仅 aliyun channel 需要
```

2. 准备环境变量：

```bash
cp .env.example .env
# 编辑 .env，至少填写 GITHUB_TOKEN
```

3. 运行爬虫：

```bash
# cvelistv5 channel（默认）
uv run vulndb-mirror crawl-cve --channel cvelistv5

# aliyun channel
uv run vulndb-mirror crawl-cve

# GHSA channel
uv run vulndb-mirror crawl-ghsa

# 全量同步（推荐，含所有 channel + GitHub 缓存）
uv run vulndb-mirror sync
```

---

## Channel: cvelistv5（默认）

从 [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) Git 仓库同步官方 CVE JSON 5.0 数据，**不需要 Playwright**。  
主要字段：description、affected products、patch/reference URL。  
数据写入 `CVELISTV5_DATA_DIR`（默认 `./output/cvelistv5/`）。

### 首次同步

```bash
uv run vulndb-mirror crawl-cve --channel cvelistv5
```

首次运行会 `git clone` 仓库到 `output/cvelistv5/cvelistv5_repo/`，然后全量导入所有 CVE 文件。

### 增量同步

再次执行同一条命令即为增量模式——自动对比上次同步的 git commit hash，只处理变动文件：

```bash
uv run vulndb-mirror crawl-cve --channel cvelistv5
```

### 强制全量重导入

```bash
uv run vulndb-mirror crawl-cve --channel cvelistv5 --full
```

### 相关环境变量

```env
CVELISTV5_DATA_DIR=./output/cvelistv5   # 数据目录，默认值
GIT_CLONE_VIA_SSH=false                  # true = 使用 SSH 协议
GIT_PROXY=socks5://127.0.0.1:1080        # 可选，git 操作走代理
```

---

## Channel: trickest_cve

从 [trickest/cve](https://github.com/trickest/cve) Git 仓库同步 CVE 数据，**不需要 Playwright**。  
主要字段：description、affected products、PoC references（GitHub 链接列表）。  
数据写入独立目录 `./output/trickest_cve/`，与其他 channel 数据完全隔离。

### 首次同步

```bash
uv run vulndb-mirror crawl-cve --channel trickest_cve
```

首次运行会：
1. `git clone https://github.com/trickest/cve.git` 到 `output/trickest_cve/trickest_repo/`
2. 遍历所有年份目录下的 `CVE-*.md` 文件（约数十万条）
3. 每条解析为 `CveRecord` 存入 storage

### 增量同步

再次执行同一条命令即为增量模式——自动对比上次同步的 git commit hash，只处理变动文件：

```bash
uv run vulndb-mirror crawl-cve --channel trickest_cve
```

### 强制全量重导入

```bash
uv run vulndb-mirror crawl-cve --channel trickest_cve --full
```

### 相关环境变量

```env
TRICKEST_DATA_DIR=./output/trickest_cve   # 数据目录，默认值
GIT_CLONE_VIA_SSH=false                    # true = 使用 SSH 协议
GIT_PROXY=socks5://127.0.0.1:1080          # 可选，git 操作走代理
SINCE=2023-01-01                           # 按年份过滤，只导入 >= 该年份的 CVE
```

---

## Channel: aliyun

抓取 [avd.aliyun.com](https://avd.aliyun.com)，通过 Playwright 渲染页面。  
丰富字段：CVSS score/vector、CWE、severity、published/modified dates。  
数据写入 `DATA_DIR`（默认 `./output/aliyun_cve/`）。

### 增量抓取

```bash
uv run vulndb-mirror crawl-cve
uv run vulndb-mirror crawl-cve --start-page 50
```

默认 `SYNC_MODE=hybrid`，会执行 `head_incremental`：

1. `head_incremental`：从第 1 页开始按 `SINCE` 做增量抓取（命中旧数据后停止）。
2. `head` 阶段默认会跳过已成功 checkpoint 的中间页（可通过 `HEAD_SKIP_OK_PAGES` 控制），并强制重查前 `HEAD_RECHECK_PAGES` 页。

这会复用已有 `page_checkpoints` 与历史元信息，不需要重跑历史结果。  
如果未设置 `SINCE`，会自动回退到上次保存的 `last_seen_date` 作为前段增量阈值。

如果需要保持旧行为（单段线性）：

```bash
SYNC_MODE=linear uv run vulndb-mirror crawl-cve
```

### 查看缺失/失败页段

```bash
uv run vulndb-mirror gaps
```

### 重试指定页

```bash
uv run vulndb-mirror retry --pages 50 51 52
```

### 相关环境变量

```env
MAX_PAGES=200
PAGE_CONCURRENCY=4
SYNC_MODE=hybrid
HEAD_SKIP_OK_PAGES=true
HEAD_RECHECK_PAGES=10
DATA_DIR=./output/aliyun_cve
RAWDB_STORAGE_BACKEND=dual
SINCE=2023-01-01   # 可选，前段增量阈值
```

---

## Channel: ghsa

从 [github/advisory-database](https://github.com/github/advisory-database) 同步 GitHub 安全公告（GHSA），**不需要 Playwright**。  
格式为 OSV JSON，每条公告一个文件。  
主要字段：`ghsa_id`、`cve_ids`（通过 aliases 字段关联）、`summary`、`details`（Markdown）、`affected`（生态系统 + 包名 + 版本范围）、`references`（含 FIX/ADVISORY 等类型）、`cwe_ids`、`github_reviewed`、`withdrawn`。  
数据写入 `GHSA_DATA_DIR`（默认 `./output/ghsa/`），SQLite 包含 3 张表：`ghsa_entries`、`ghsa_cve_aliases`（CVE 反查）、`ghsa_affected`（生态系统/包名查询）。

### 首次同步

```bash
uv run vulndb-mirror crawl-ghsa
```

首次运行会 shallow-clone `github/advisory-database` 到 `GHSA_DATA_DIR/advisory-database/`，然后全量导入所有 `.json` 文件。

### 增量同步

再次执行同一条命令即为增量模式——通过 git diff 对比上次同步的 commit hash，只处理变动文件：

```bash
uv run vulndb-mirror crawl-ghsa
```

### 强制全量重导入

```bash
uv run vulndb-mirror crawl-ghsa --full
```

### 相关环境变量

```env
GHSA_DATA_DIR=./output/ghsa    # advisory-database clone 目录，默认值
GHSA_SQLITE_PATH=              # 留空则使用 GHSA_DATA_DIR/ghsa.db
GIT_CLONE_VIA_SSH=false        # true = 使用 SSH 协议
GIT_PROXY=socks5://127.0.0.1:1080   # 可选，git 操作走代理
```

---

## 启动 API 服务

```bash
uv run vulndb-mirror api
```

如果 `8787` 端口已被占用：

```bash
RAWDB_API_PORT=8791 uv run vulndb-mirror api
```

启动后访问：

- `http://127.0.0.1:<RAWDB_API_PORT>/docs`：OpenAPI 文档（默认端口 `8787`）

## 启动 Web 前端

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

Web UI：`http://127.0.0.1:3000`

前端功能：
- 固定左侧过滤栏，含汇总统计
- 列表内联详情卡片
- 右侧抽屉展示完整 CVE 详情
- 直链跳转详情 / 引用 / patch URL
- 可配置的 PoC 状态启发式标注
- 日期过滤收起在高级选项中

---

## 完整环境变量

```env
# 通用
CHANNEL=cvelistv5
SYNC_MODE=hybrid
HEAD_SKIP_OK_PAGES=true
HEAD_RECHECK_PAGES=10
LOG_DIR=./logs

# GitHub API
GITHUB_TOKEN=ghp_...

# aliyun channel
MAX_PAGES=200
PAGE_CONCURRENCY=4
DATA_DIR=./output/aliyun_cve
RAWDB_STORAGE_BACKEND=dual

# trickest channel
TRICKEST_DATA_DIR=./output/trickest_cve
GIT_CLONE_VIA_SSH=false
# GIT_PROXY=socks5://127.0.0.1:1080

# cvelistv5 channel
CVELISTV5_DATA_DIR=./output/cvelistv5

# GHSA channel
GHSA_DATA_DIR=./output/ghsa
# GHSA_SQLITE_PATH=

# GitHub 缓存
GITHUB_SBOM_CONCURRENCY=4
GITHUB_SBOM_HOURLY_BUDGET=4500
# GITHUB_SBOM_SQLITE_PATH=

GITHUB_LANGUAGES_CONCURRENCY=4
GITHUB_LANGUAGES_HOURLY_BUDGET=4500
# GITHUB_LANGUAGES_SQLITE_PATH=

# API 服务
RAWDB_API_HOST=127.0.0.1
RAWDB_API_PORT=8787
```

## 输出目录

### aliyun channel

- 原始文件：`output/aliyun_cve/cve/CVE-*.json`
- SQLite DB：`output/aliyun_cve/raw.db`
- 页面/元信息状态：`output/aliyun_cve/.rawdb.state.json`
- 日志：`logs/*-crawler.log`

### trickest_cve channel

- Git 仓库 clone：`output/trickest_cve/trickest_repo/`
- 原始文件：`output/trickest_cve/cve/CVE-*.json`
- SQLite DB：`output/trickest_cve/raw.db`
- 同步状态（last commit）：`output/trickest_cve/.trickest_state.json`

### cvelistv5 channel

- Git 仓库 clone：`output/cvelistv5/cvelistv5_repo/`
- 原始文件：`output/cvelistv5/cve/CVE-*.json`
- SQLite DB：`output/cvelistv5/raw.db`
- 同步状态（last commit）：`output/cvelistv5/.cvelistv5_state.json`

### ghsa channel

- Git 仓库 clone：`output/ghsa/advisory-database/`
- SQLite DB：`output/ghsa/ghsa.db`（含 `ghsa_entries`、`ghsa_cve_aliases`、`ghsa_affected` 三张表）
- 同步状态（last commit）：`output/ghsa/.ghsa_state.json`

状态文件/数据库中的同步游标（自动兼容旧状态）：

- `head_last_stop_page`：上次前段增量停止页（aliyun）
- `last_commit` / `last_sync`：上次同步 commit hash 与时间（trickest / cvelistv5 / ghsa）

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
