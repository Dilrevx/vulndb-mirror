# vulndb-mirror

漏洞镜像库，包含两个独立 Python 包：

- `vulndb_mirror`：镜像抓取 + storage + server + CLI
- `logic_vulns`：分析逻辑（`filter` + `tracer`）

`vulndb_mirror` 集成了 GitHub API 缓存：对 CVE 引用的仓库异步拉取依赖图（SBOM）和语言组成，缓存到本地供查询。

## 数据 Channel

| Channel | 数据源 | 特点 |
|---------|--------|------|
| `cvelistv5`（默认）| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | 官方 CVE JSON 5.0，含 patch/reference URL |
| `trickest_cve` | [trickest/cve](https://github.com/trickest/cve) | 含 PoC/GitHub 引用，通过 git clone/pull 同步 |
| `aliyun` | [avd.aliyun.com](https://avd.aliyun.com) | 含 CVSS / CWE / severity，需 Playwright |

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
uv run vulndb-mirror sync                          # 默认 cvelistv5，每小时一轮
uv run vulndb-mirror sync --channel cvelistv5 trickest_cve   # 多 channel
uv run vulndb-mirror sync --interval 7200          # 自定义间隔（秒）
```

每轮依次执行：① 同步 CVE 数据 → ② 补全 GitHub 依赖图 → ③ 补全 GitHub 语言组成。

**启动 API 服务：**

```bash
uv run vulndb-mirror api
```

**启动 Web 前端：**

```bash
cd web && npm install && npm run dev:full
```

默认会自动启动前端服务在 `3000` 端口和后端 API服务在 `8787` 端口。前端通过 Next.js 的反向代理（Rewrite）自动将 `/api/*` 的请求路由到后端。

## CLI

### `sync` — 定时全量同步（推荐）

```bash
uv run vulndb-mirror sync [--channel cvelistv5 trickest_cve] [--interval 3600]
                          [--patch-only] [--github-max-repos 500] [--github-max-seconds 1800]
```

每轮循环：
1. 对每个 channel 执行增量 CVE 同步
2. 从新 CVE 中提取 GitHub 仓库入队，运行 SBOM worker
3. 同上，运行语言组成 worker
4. 等待至下一个 `--interval` 秒，重复

`Ctrl-C` / `SIGTERM` 在当前阶段结束后优雅退出。

### CVE 数据同步（单次）

**cvelistv5 / trickest_cve channel**

```bash
uv run vulndb-mirror crawl --channel cvelistv5
uv run vulndb-mirror crawl --channel trickest_cve
uv run vulndb-mirror crawl --channel cvelistv5 --full   # 强制全量重导入
```

**Aliyun channel**

```bash
uv run vulndb-mirror crawl                  # 增量同步
uv run vulndb-mirror gaps                   # 查看缺失页段
uv run vulndb-mirror retry --pages 50 51    # 重试指定页
```

默认 `SYNC_MODE=hybrid`：先从第 1 页做前段增量，跳过已有成功 checkpoint 的中间页，保留前 `HEAD_RECHECK_PAGES` 页强制重查。如需旧的线性行为：`SYNC_MODE=linear uv run vulndb-mirror crawl`

### GitHub 缓存服务（独立长驻，可替代 `sync`）

对 CVE 引用的 GitHub 仓库调用 GitHub API，将依赖图（SBOM）和语言组成缓存到本地。需要设置 `GITHUB_TOKEN`（PAT，5000 req/h，两个服务共享配额）。

| 服务 | 命令 | 数据内容 |
|------|------|----------|
| 依赖图 | `github-deps` | SBOM 依赖包列表，支持反查"哪些 CVE 影响某个包" |
| 语言组成 | `github-languages` | 各语言字节数，支持反查"哪些仓库用某语言编写" |

```bash
uv run vulndb-mirror github-deps run
uv run vulndb-mirror github-languages run

# 两个服务支持相同的选项
--channel cvelistv5 trickest_cve   # 扫描多个 channel（默认 cvelistv5）
--patch-only                        # 只处理 patch_url 中的高优先级仓库
--discover-interval 1800            # 发现间隔秒数（默认 3600）
```

**服务循环**：启动 → 扫描近 30 天 CVE 入队 → 持续拉取（受 hourly budget 限速）→ 队列清空后补充历史数据 → 每隔 `--discover-interval` 秒重复。

**缓存时效**：无固定过期时间。仓库被抓取后保持 `fetched` 状态；当新 CVE 再次引用同一仓库时，自动重置为 `pending` 触发重新拉取。`skip_404` / `skip_403` 是终态，不会被重置。

**优先级**：`priority=0` 为 `patch_urls` 中的仓库（高价值），`priority=1` 为仅在 `references` 中出现的仓库。

```bash
uv run vulndb-mirror github-deps stats
uv run vulndb-mirror github-languages stats
```

### API 服务

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
| `POST` | `/ops/github-deps/discover` | 从 CVE 提取仓库入队（`?channel=&since_iso=&limit=`） |
| `POST` | `/ops/github-deps/sync` | 拉取 SBOM 队列（`?max_repos=&max_seconds=&priority=`） |
| `POST` | `/ops/github-languages/discover` | 从 CVE 提取仓库入队（语言缓存） |
| `POST` | `/ops/github-languages/sync` | 拉取语言队列（`?max_repos=&max_seconds=&priority=`） |

## Web 前端

展示 CVE 列表、详情及 GitHub 仓库的依赖图和语言组成，对接上方 API 服务。

```bash
cd web
cp .env.local.example .env.local
npm install
npm run dev
```

## 参考文档

- `docs/server-frontend-migration.md`：前后端分离迁移记录
- `docs/rawdb-package-evaluation.md`：存储方案评估
- `docs/usage.md`：详细使用说明
