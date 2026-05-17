# Server + Frontend Migration Guide (Quick Copy)

This guide focuses on a minimal copy-and-run path.

## Package split

- `vulndb_mirror`: mirror crawler + storage + server + config + CLI
- `logic_vulns`: filter/tracer logic

Removed:

- `vulndb_channels`
- starter template
- all `aliyun_crawler` compatibility

## 1) Backend quick copy

Copy into target project:

- `src/vulndb_mirror/`
- `src/logic_vulns/`

Install dependencies:

```bash
uv add fastapi uvicorn pydantic pydantic-settings httpx[socks] playwright playwright-stealth beautifulsoup4 pyyaml
uv run playwright install chromium
```

Bootstrap server:

```python
from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.server.api import create_app
from vulndb_mirror.storage.cve.aliyun_ingest import AliyunIngestService
from vulndb_mirror.storage.cve.factory import build_cve_repository

settings = CrawlerSettings()
repository = build_cve_repository(settings)
service = AliyunIngestService(settings.to_crawl_config(), repository)
app = create_app(
    repositories={"aliyun": repository},
    services={"aliyun": service},
)
```

Run:

```bash
uvicorn your_module:app --host 0.0.0.0 --port 8787
```

## 2) Frontend quick copy

Copy:

- `web/`

Set env:

- `NEXT_PUBLIC_API_BASE=/api` (In `web/.env.local` to use Next.js proxy)

Run:

```bash
cd web
npm install
npm run dev
```

## 3) Import map

| Symbol | Path |
|--------|------|
| `create_app` | `vulndb_mirror.server.api` |
| `CrawlerSettings` | `vulndb_mirror.config` |
| `build_cve_repository` | `vulndb_mirror.storage.cve.factory` |
| `AliyunIngestService` | `vulndb_mirror.storage.cve.aliyun_ingest` |
| `CvelistV5IngestService` | `vulndb_mirror.storage.cve.cvelistv5_ingest` |
| `GhsaIngestService` | `vulndb_mirror.storage.ghsa.ingest` |
| `GhsaRepository` | `vulndb_mirror.storage.ghsa.repository` |
| `FilterPipeline` | `logic_vulns.filter` |
| `CalltraceExplorer` | `logic_vulns.tracer` |

GHSA is an optional data source. To enable it, pass `ghsa_repo` and `ghsa_service` to `create_app`:

```python
from vulndb_mirror.storage.ghsa.ingest import GhsaIngestService
from vulndb_mirror.storage.ghsa.repository import GhsaRepository

ghsa_repo = GhsaRepository(db_path=settings.ghsa_sqlite_path or "./output/ghsa/ghsa.db")
ghsa_service = GhsaIngestService(settings, ghsa_repo)
app = create_app(
    repositories={"aliyun": repository},
    services={"aliyun": service},
    ghsa_repo=ghsa_repo,
    ghsa_service=ghsa_service,
)
```

## 4) Recommended target layout

```text
src/
  vulndb_mirror/
  logic_vulns/
web/
```

## 5) Verification checklist

1. `GET /health` returns `{"status": "ok"}`.
2. `GET /raw?page=1&page_size=20` returns items.
3. Frontend can fetch and paginate vulnerabilities.
4. Frontend can execute gaps/checkpoints/retry operations.
