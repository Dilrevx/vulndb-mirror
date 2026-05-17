# vulndb-mirror

漏洞镜像库，聚合多个公开漏洞数据源，提供统一的本地存储、REST API 和 Web 前端。包含两个独立 Python 包：

- `vulndb_mirror`：镜像抓取 + storage + server + CLI
- `logic_vulns`：分析逻辑（`filter` + `tracer`）

`vulndb_mirror` 集成了 GitHub API 缓存：对 CVE 引用的仓库异步拉取依赖图（SBOM）和语言组成，缓存到本地供查询。

## 数据 Channel

| Channel | 数据源 | 特点 |
|---------|--------|------|
| `cvelistv5`（默认）| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | 官方 CVE JSON 5.0，含 patch/reference URL |
| `trickest_cve` | [trickest/cve](https://github.com/trickest/cve) | 含 PoC/GitHub 引用，通过 git clone/pull 同步 |
| `aliyun` | [avd.aliyun.com](https://avd.aliyun.com) | 含 CVSS / CWE / severity，需 Playwright |
| `ghsa` | [github/advisory-database](https://github.com/github/advisory-database) | GitHub 安全公告，OSV 格式，含受影响包/版本范围/CWE |

## 安装

```bash
uv sync
uv run playwright install chromium   # 仅 aliyun channel 需要
cp .env.example .env
# 编辑 .env，至少填写 GITHUB_TOKEN
```

## 快速运行

**一条命令启动全量同步（推荐放 tmux）：**

```bash
uv run vulndb-mirror sync                                          # 默认 cvelistv5，每小时一轮
uv run vulndb-mirror sync --channel cvelistv5 trickest_cve ghsa   # 多 channel
uv run vulndb-mirror sync --interval 7200                          # 自定义间隔（秒）
```

每轮依次执行：① 同步 CVE channels → ② 同步 GHSA → ③ 补全 GitHub 依赖图 → ④ 补全 GitHub 语言组成。

**启动 API 服务：**

```bash
uv run vulndb-mirror api
```

**启动 Web 前端：**

```bash
cd web && npm install && npm run dev:full
```

默认会自动启动前端服务在 `3000` 端口和后端 API 服务在 `8787` 端口。前端通过 Next.js 的反向代理（Rewrite）自动将 `/api/*` 的请求路由到后端。

## CLI

### `sync` — 定时全量同步（推荐）

```bash
uv run vulndb-mirror sync [--channel cvelistv5 trickest_cve ghsa] [--interval 3600]
                          [--patch-only] [--github-max-repos 500] [--github-max-seconds 1800]
```

每轮循环：
1. 对每个 CVE channel 执行增量同步
2. 同步 GHSA（若 `ghsa` 在 channel 列表中）
3. 从新 CVE 中提取 GitHub 仓库入队，运行 SBOM worker
4. 同上，运行语言组成 worker
5. 等待至下一个 `--interval` 秒，重复

`Ctrl-C` / `SIGTERM` 在当前阶段结束后优雅退出。

### `crawl-cve` — CVE 数据单次同步

**cvelistv5 / trickest_cve channel**

```bash
uv run vulndb-mirror crawl-cve --channel cvelistv5
uv run vulndb-mirror crawl-cve --channel trickest_cve
uv run vulndb-mirror crawl-cve --channel cvelistv5 --full   # 强制全量重导入
```

**aliyun channel**

```bash
uv run vulndb-mirror crawl-cve                  # 增量同步（默认 aliyun）
uv run vulndb-mirror crawl-cve --start-page 50  # 从指定页开始
```

默认 `SYNC_MODE=hybrid`：先从第 1 页做前段增量，跳过已有成功 checkpoint 的中间页，保留前 `HEAD_RECHECK_PAGES` 页强制重查。如需旧的线性行为：`SYNC_MODE=linear uv run vulndb-mirror crawl-cve`

> `crawl` 是 `crawl-cve` 的隐藏别名，保持向后兼容。

### `crawl-ghsa` — GHSA 单次同步

```bash
uv run vulndb-mirror crawl-ghsa          # 增量同步（自动 git pull + diff）
uv run vulndb-mirror crawl-ghsa --full   # 强制全量重导入
```

首次运行会 shallow-clone `github/advisory-database` 到 `GHSA_DATA_DIR`，后续运行通过 git diff 只处理变动文件。

### `gaps` — 查看 aliyun 缺失页段

```bash
uv run vulndb-mirror gaps
```

### `retry` — 重试 aliyun 指定页

```bash
uv run vulndb-mirror retry --pages 50 51 52
```

### `github-deps` — GitHub 依赖图缓存服务

```bash
uv run vulndb-mirror github-deps run    # 启动长驻 worker
uv run vulndb-mirror github-deps stats  # 查看缓存统计
```

### `github-languages` — GitHub 语言组成缓存服务

```bash
uv run vulndb-mirror github-languages run    # 启动长驻 worker
uv run vulndb-mirror github-languages stats  # 查看缓存统计
```

两个服务支持相同的选项：

```
--channel cvelistv5 trickest_cve   # 扫描多个 channel（默认 cvelistv5）
--patch-only                        # 只处理 patch_url 中的高优先级仓库
--discover-interval 1800            # 发现间隔秒数（默认 3600）
```

### `api` — 启动 API 服务

```bash
uv run vulndb-mirror api
RAWDB_API_PORT=8791 uv run vulndb-mirror api
```

## 环境变量

```env
# 通用
CHANNEL=cvelistv5
SYNC_MODE=hybrid
HEAD_SKIP_OK_PAGES=true
HEAD_RECHECK_PAGES=10

# GitHub API
GITHUB_TOKEN=ghp_...

# trickest channel
TRICKEST_DATA_DIR=./output/trickest_cve
GIT_CLONE_VIA_SSH=false
GIT_PROXY=socks5://127.0.0.1:1080   # 可选，git 操作代理

# cvelistv5 channel
CVELISTV5_DATA_DIR=./output/cvelistv5

# GHSA channel
GHSA_DATA_DIR=./output/ghsa          # advisory-database clone 目录
GHSA_SQLITE_PATH=                    # 留空则使用 GHSA_DATA_DIR/ghsa.db

# GitHub 缓存（两个服务各自独立配置）
GITHUB_SBOM_CONCURRENCY=4
GITHUB_SBOM_HOURLY_BUDGET=4500
GITHUB_SBOM_SQLITE_PATH=             # 留空则使用 cvelistv5 的 raw.db

GITHUB_LANGUAGES_CONCURRENCY=4
GITHUB_LANGUAGES_HOURLY_BUDGET=4500
GITHUB_LANGUAGES_SQLITE_PATH=        # 留空则使用 cvelistv5 的 raw.db

# API 服务
RAWDB_API_HOST=127.0.0.1
RAWDB_API_PORT=8787
```

## API 路由

### CVE 数据

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/health` | 健康检查 |
| `GET` | `/channels` | 已配置的 channel 列表 |
| `GET` | `/raw/{cve_id}` | 查询单条 CVE（`?channel=cvelistv5`） |
| `GET` | `/raw` | 分页查询（`q`, `modified_from`, `has_patch`, `page`, `page_size`, `channel`） |

### GHSA 安全公告

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/ghsa/stats` | 统计信息（条目数、生态系统分布） |
| `GET` | `/ghsa/by-cve/{cve_id}` | 通过 CVE ID 查关联的 GHSA 条目 |
| `GET` | `/ghsa/{ghsa_id}` | 查询单条 GHSA |
| `GET` | `/ghsa` | 分页查询（`ecosystem`, `package_name`, `page`, `page_size`） |

### GitHub 依赖图

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/github-deps/stats` | 缓存统计（状态分布、包总数） |
| `GET` | `/github-deps/{owner}/{repo}` | 某仓库的 SBOM 及依赖包列表 |
| `GET` | `/github-deps/by-package` | 反查：哪些仓库依赖了某个包（`?name=lodash&ecosystem=npm`） |

### GitHub 语言组成

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/github-languages/stats` | 缓存统计（状态分布、语言分布） |
| `GET` | `/github-languages/{owner}/{repo}` | 某仓库的语言构成（含百分比） |
| `GET` | `/github-languages/by-language` | 反查：哪些仓库使用了某语言（`?name=Python`） |

### 运维

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/ops/sync` | 触发增量同步（`?channel=`） |
| `POST` | `/ops/aliyun/retry` | 重试指定页 |
| `GET` | `/ops/aliyun/checkpoints` | checkpoint 状态 |
| `GET` | `/ops/aliyun/gaps` | 缺失页段 |
| `POST` | `/ops/ghsa/sync` | 触发 GHSA 增量同步（`?full=false`） |
| `POST` | `/ops/github-deps/discover` | 从 CVE 提取仓库入队（`?channel=&since_iso=&limit=`） |
| `POST` | `/ops/github-deps/sync` | 拉取 SBOM 队列（`?max_repos=&max_seconds=&priority=`） |
| `POST` | `/ops/github-languages/discover` | 从 CVE 提取仓库入队（语言缓存） |
| `POST` | `/ops/github-languages/sync` | 拉取语言队列（`?max_repos=&max_seconds=&priority=`） |

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

- **不重复拉取**：已 `fetched` 的 repo 只在有新 CVE 引用时才会重新检查 BOM 更新
- **优先队列**：`priority=0`（patch URL 来源）始终先于 `priority=1`（reference 来源）处理
- **增量 discover**：sync 循环在第一轮全量扫描后，后续轮次仅扫描增量 CVE 条目（`since_iso`）
- **`enqueued_at` 更新**：repo 因新 CVE 重新入队时 `enqueued_at` 会更新，使其排到同优先级队尾
- **404/403 永久跳过**：这些状态表示 repo 本质不可达，不会浪费 API budget 重试
- **error 可重试**：500/网络异常等瞬时错误，当引用了该 repo 的新 CVE 出现时给予重试机会

### SBOM 与 Languages 的 304 行为差异

GitHub `/languages` 端点返回 `ETag`，支持 `If-None-Match` 条件请求，缓存命中时返回 **304 Not Modified**，不消耗 API quota。

GitHub `/dependency-graph/sbom` 端点**不返回 `ETag`**，每次请求均为完整 **200 OK** 响应，始终消耗 API quota。这是 GitHub API 的平台限制，不影响队列推进正确性，但意味着 SBOM 缓存的刷新会比 languages 慢。

## Web 前端

展示 CVE 列表、详情及 GitHub 仓库的依赖图和语言组成，对接上方 API 服务。

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

前端功能：
- 固定左侧过滤栏，含汇总统计
- 列表内联详情卡片
- 右侧抽屉展示完整 CVE 详情
- 直链跳转详情 / 引用 / patch URL
- 可配置的 PoC 状态启发式标注
- 日期过滤收起在高级选项中

## 参考文档

- `docs/usage.md`：详细使用说明
- `docs/server-frontend-migration.md`：前后端分离迁移指南
- `docs/rawdb-package-evaluation.md`：存储方案评估
