# vulndb-mirror

漏洞镜像库，包含两个独立 Python 包：

- `vulndb_mirror`: 镜像抓取 + storage + server + CLI
- `logic_vulns`: 分析逻辑（`filter` + `tracer`）

支持三个数据 channel：

| Channel | 数据源 | 特点 |
|---------|--------|------|
| `aliyun`（默认）| [avd.aliyun.com](https://avd.aliyun.com) | 含 CVSS / CWE / severity，需 Playwright |
| `trickest_cve` | [trickest/cve](https://github.com/trickest/cve) Git 仓库 | 含 PoC/GitHub 引用，通过 git clone/pull 同步 |
| `cvelistv5` | [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) Git 仓库 | 官方 CVE JSON 5.0，含 patch/reference URL |

## 快速安装

```bash
uv sync
uv run playwright install chromium   # 仅 aliyun channel 需要
cp .env.example .env
```

## CLI

### Aliyun channel（默认）

```bash
uv run vulndb-mirror crawl
uv run vulndb-mirror gaps
uv run vulndb-mirror retry --pages 50 51
uv run vulndb-mirror api
```

`crawl` 默认使用 `SYNC_MODE=hybrid`：

1. `head_incremental`：从第 1 页按 `SINCE`（未设置时回退到 `last_seen_date`）做前段增量。
2. `head` 阶段默认跳过已有成功 checkpoint 的中间页，保留前 `HEAD_RECHECK_PAGES` 页强制重查。

如需旧的单段线性行为：

```bash
SYNC_MODE=linear uv run vulndb-mirror crawl
```

### Trickest CVE channel

```bash
# 首次同步（clone 仓库 + 全量导入）
uv run vulndb-mirror crawl --channel trickest_cve

# 增量同步（仅处理上次 commit 以来变动的文件）
uv run vulndb-mirror crawl --channel trickest_cve

# 强制全量重导入
uv run vulndb-mirror crawl --channel trickest_cve --full
```

数据写入 `./output/trickest_cve/`。

### cvelistV5 channel

```bash
# 首次同步（clone 仓库 + 全量导入）
uv run vulndb-mirror crawl --channel cvelistv5

# 增量同步
uv run vulndb-mirror crawl --channel cvelistv5

# 强制全量重导入
uv run vulndb-mirror crawl --channel cvelistv5 --full
```

数据写入 `./output/cvelistv5/`。

### GitHub 依赖图缓存（github-deps）

对 CVE 引用的 GitHub 仓库调用 GitHub Dependency Graph API，将 SBOM 依赖清单缓存到本地，支持正向查询（某仓库依赖了哪些库）和反向查询（哪些 CVE 间接影响某个包）。

需要设置 `GITHUB_TOKEN`（Personal Access Token，5000 req/h）。

**启动长驻服务**（推荐在 tmux 中运行）：

```bash
# 扫描 cvelistv5 channel，每小时重新发现近 30 天的 CVE
uv run vulndb-mirror github-deps run

# 同时扫描多个 channel
uv run vulndb-mirror github-deps run --channel cvelistv5 trickest_cve

# 只处理高优先级（patch_url 中的仓库）
uv run vulndb-mirror github-deps run --patch-only

# 自定义发现间隔（秒）
uv run vulndb-mirror github-deps run --discover-interval 1800
```

服务行为：
1. 启动时立即扫描近 30 天的 CVE，提取 GitHub 仓库入队
2. 持续拉取队列，受 hourly budget 控制；限速时自动等待，不退出
3. 队列清空后，扫描全量 CVE（无时间过滤）补充历史数据
4. 每隔 `--discover-interval` 秒重复步骤 1，循环运行
5. `Ctrl-C` / `SIGTERM` 优雅退出（当前批次处理完后停止）

**时效性说明**：SBOM 缓存没有固定过期时间。一个仓库被抓取后会保持 `fetched` 状态，直到有新的 CVE 再次引用它——此时 `enqueue_many` 会把状态重置为 `pending`，触发重新拉取。这样既避免了无意义的重复请求，又保证了"有新漏洞关联时依赖数据是最新的"。`skip_404` / `skip_403` 是终态，不会被新 CVE 重置（仓库不存在或无 SBOM 权限，重试无意义）。

优先级说明：
- `priority=0`：出现在 `patch_urls` 中的仓库（高价值，优先处理）
- `priority=1`：仅出现在 `references` 中的仓库

`crawl --channel cvelistv5/trickest_cve` 同步完成后会自动触发一次 discover，与服务并行运行时是幂等的。

**查看缓存统计**：

```bash
uv run vulndb-mirror github-deps stats
```

## 环境变量

常用配置（写入 `.env`）：

```env
# 通用
CHANNEL=aliyun          # 默认 channel
SYNC_MODE=hybrid
HEAD_SKIP_OK_PAGES=true
HEAD_RECHECK_PAGES=10

# GitHub API（github-deps 必须）
GITHUB_TOKEN=ghp_...

# trickest channel
TRICKEST_DATA_DIR=./output/trickest_cve
GIT_CLONE_VIA_SSH=false          # 改为 true 以使用 git@github.com SSH 协议
GIT_PROXY=socks5://127.0.0.1:1080  # 可选，git 操作代理

# cvelistv5 channel
CVELISTV5_DATA_DIR=./output/cvelistv5

# GitHub SBOM 缓存
GITHUB_SBOM_CONCURRENCY=4                 # 并发线程数
GITHUB_SBOM_HOURLY_BUDGET=4500            # 每小时最大请求数（留 500 给其他调用）
GITHUB_SBOM_SQLITE_PATH=                  # 留空则使用 cvelistv5 的 raw.db

# API 服务
RAWDB_API_HOST=127.0.0.1
RAWDB_API_PORT=8787
```

## FastAPI

启动：

```bash
uv run vulndb-mirror api
# 或指定端口
RAWDB_API_PORT=8791 uv run vulndb-mirror api
```

### 通用路由

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/health` | 健康检查 |
| `GET` | `/channels` | 已配置的 channel 列表 |
| `GET` | `/raw/{cve_id}` | 查询单条 CVE（`?channel=cvelistv5`） |
| `GET` | `/raw` | 分页查询（`q`, `modified_from`, `has_patch`, `page`, `page_size`, `channel`） |

### 运维路由

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/ops/sync` | 触发增量同步（`?channel=`） |
| `POST` | `/ops/aliyun/retry` | 重试指定页（aliyun） |
| `GET` | `/ops/aliyun/checkpoints` | 查看 checkpoint 状态 |
| `GET` | `/ops/aliyun/gaps` | 查看缺失页段 |
| `POST` | `/ops/github-deps/discover` | 从 CVE 数据提取仓库入队（`?channel=&since_iso=&limit=`） |
| `POST` | `/ops/github-deps/sync` | 拉取 SBOM 队列（`?max_repos=&max_seconds=&priority=`） |

### GitHub 依赖图路由

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/github-deps/stats` | 缓存统计（状态分布、包总数） |
| `GET` | `/github-deps/{owner}/{repo}` | 查询某仓库的 SBOM 缓存及依赖包列表 |
| `GET` | `/github-deps/by-package` | 反查：哪些仓库依赖了某个包（`?name=lodash&ecosystem=npm`） |

## Web 前端

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

## 迁移文档

- `docs/server-frontend-migration.md`
- `docs/rawdb-package-evaluation.md`
- `docs/usage.md`
