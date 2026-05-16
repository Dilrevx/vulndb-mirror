from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from vulndb_mirror.storage.github_deps.ingest_service import (
    GithubSbomIngestService,
)
from vulndb_mirror.storage.github_deps.repository import GitHubSbomRepository
from vulndb_mirror.storage.github_language.ingest_service import (
    GithubLanguagesIngestService,
)
from vulndb_mirror.storage.github_language.repository import GitHubLanguagesRepository
from vulndb_mirror.storage.raw.ingest_service import RawIngestService
from vulndb_mirror.storage.raw.raw_models import RetryRequest
from vulndb_mirror.storage.raw.repositories import RawRepository


def create_app(
    repositories: dict[str, RawRepository],
    services: dict[str, Any],
    *,
    sbom_repo: Optional[GitHubSbomRepository] = None,
    sbom_service: Optional[GithubSbomIngestService] = None,
    languages_repo: Optional[GitHubLanguagesRepository] = None,
    languages_service: Optional[GithubLanguagesIngestService] = None,
) -> FastAPI:
    channel_names = list(repositories.keys())

    def _resolve_repo(channel: str | None) -> RawRepository:
        key = channel or "aliyun"
        repo = repositories.get(key)
        if repo is None:
            raise HTTPException(status_code=400, detail=f"unknown channel: {key}")
        return repo

    def _resolve_service(channel: str | None) -> Any:
        key = channel or "aliyun"
        svc = services.get(key)
        if svc is None:
            raise HTTPException(status_code=400, detail=f"unknown channel: {key}")
        return svc

    app = FastAPI(title="VulnDB Mirror API", version="0.2.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---- Generic (all channels) -----------------------------------------

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/channels")
    def channels() -> dict[str, list[str]]:
        return {"channels": channel_names}

    @app.get("/raw/{cve_id}")
    def get_raw(
        cve_id: str,
        channel: Optional[str] = Query(default=None),
    ):
        item = _resolve_repo(channel).get_raw(cve_id)
        if item is None:
            raise HTTPException(status_code=404, detail="not found")
        return item.model_dump()

    @app.get("/raw")
    def query_raw(
        q: str | None = Query(default=None, description="Keyword search"),
        modified_from: str | None = Query(default=None),
        modified_to: str | None = Query(default=None),
        has_patch: bool | None = Query(default=None, description="Filter by patch presence"),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=500),
        channel: Optional[str] = Query(default=None),
    ):
        result = _resolve_repo(channel).query_raw(
            q=q,
            modified_from=modified_from,
            modified_to=modified_to,
            has_patch=has_patch,
            page=page,
            page_size=page_size,
        )
        return result.model_dump(mode="json")

    # ---- Ops: unified sync ----------------------------------------------

    @app.post("/ops/sync")
    def ops_sync(
        channel: Optional[str] = Query(default=None),
        start_page: int | None = Query(default=None, ge=1),
    ):
        svc = _resolve_service(channel)
        if isinstance(svc, RawIngestService):
            result = svc.crawl_incremental(start_page=start_page)
        else:
            result = svc.sync()
        return result.model_dump()

    # ---- Ops: aliyun-specific -------------------------------------------

    @app.post("/ops/aliyun/retry")
    def ops_aliyun_retry(req: RetryRequest):
        svc = services.get("aliyun")
        if svc is None:
            raise HTTPException(status_code=404, detail="aliyun channel not configured")
        result = svc.retry_pages(req.pages)
        return result.model_dump()

    @app.get("/ops/aliyun/checkpoints")
    def ops_aliyun_checkpoints(status: str | None = Query(default=None)):
        repo = repositories.get("aliyun")
        if repo is None:
            raise HTTPException(status_code=404, detail="aliyun channel not configured")
        return {
            "items": [cp.model_dump() for cp in repo.list_checkpoints(status=status)],
            "meta": repo.get_meta().model_dump(),
        }

    @app.get("/ops/aliyun/gaps")
    def ops_aliyun_gaps(
        max_page: int = Query(..., ge=1),
        include_failed: bool = Query(default=True),
    ):
        repo = repositories.get("aliyun")
        if repo is None:
            raise HTTPException(status_code=404, detail="aliyun channel not configured")
        return {
            "gaps": [
                g.model_dump()
                for g in repo.get_gaps(max_page=max_page, include_failed=include_failed)
            ],
            "meta": repo.get_meta().model_dump(),
        }

    # ---- GitHub SBOM cache ---------------------------------------------

    def _require_sbom_repo() -> GitHubSbomRepository:
        if sbom_repo is None:
            raise HTTPException(
                status_code=503, detail="github-deps not configured"
            )
        return sbom_repo

    def _require_sbom_service() -> GithubSbomIngestService:
        if sbom_service is None:
            raise HTTPException(
                status_code=503, detail="github-deps not configured"
            )
        return sbom_service

    @app.get("/github-deps/stats")
    def github_deps_stats():
        return _require_sbom_repo().stats()

    @app.get("/github-deps/top-packages")
    def github_deps_top_packages(
        limit: int = Query(default=50, ge=1, le=500),
        ecosystem: Optional[str] = Query(default=None),
    ):
        return {"items": _require_sbom_repo().top_packages(limit=limit, ecosystem=ecosystem or None)}

    @app.get("/github-deps/ecosystems")
    def github_deps_ecosystems():
        return {"items": _require_sbom_repo().ecosystems()}

    @app.get("/github-deps/by-package")
    def github_deps_by_package(
        name: str = Query(..., min_length=1),
        ecosystem: Optional[str] = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ):
        return {
            "items": _require_sbom_repo().query_by_package(
                ecosystem=ecosystem, name=name, limit=limit
            )
        }

    @app.get("/github-deps/{owner}/{repo}")
    def github_deps_by_repo(owner: str, repo: str):
        item = _require_sbom_repo().query_by_repo(owner.lower(), repo.lower())
        if item is None:
            raise HTTPException(status_code=404, detail="not found")
        return item

    @app.post("/ops/github-deps/discover")
    def ops_github_deps_discover(
        channel: str = Query(default="cvelistv5"),
        since_iso: Optional[str] = Query(default=None),
        limit: Optional[int] = Query(default=None, ge=1),
    ):
        svc = _require_sbom_service()
        if channel not in repositories:
            raise HTTPException(status_code=400, detail=f"unknown channel: {channel}")
        # Re-bind raw_repo so discover scans the requested channel.
        svc.raw_repo = repositories[channel]
        result = svc.discover_from_recent(
            channel=channel, since_iso=since_iso, limit=limit
        )
        return result.model_dump()

    @app.post("/ops/github-deps/sync")
    def ops_github_deps_sync(
        max_repos: int = Query(default=200, ge=1),
        max_seconds: int = Query(default=300, ge=1),
        priority: Optional[int] = Query(default=None, ge=0, le=1),
    ):
        result = _require_sbom_service().run_worker(
            max_repos=max_repos,
            max_seconds=max_seconds,
            priority=priority,
        )
        return result.model_dump()

    # ---- GitHub Languages cache -----------------------------------------

    def _require_languages_repo() -> GitHubLanguagesRepository:
        if languages_repo is None:
            raise HTTPException(
                status_code=503, detail="github-languages not configured"
            )
        return languages_repo

    def _require_languages_service() -> GithubLanguagesIngestService:
        if languages_service is None:
            raise HTTPException(
                status_code=503, detail="github-languages not configured"
            )
        return languages_service

    @app.get("/github-languages/stats")
    def github_languages_stats():
        return _require_languages_repo().stats()

    @app.get("/github-languages/top-languages")
    def github_languages_top_languages(
        limit: int = Query(default=50, ge=1, le=500),
    ):
        return {"items": _require_languages_repo().top_languages(limit=limit)}

    @app.get("/github-languages/cwe-stats")
    def github_languages_cwe_stats(
        limit: int = Query(default=100, ge=1, le=500),
    ):
        return {"items": _require_languages_repo().cwe_language_stats(limit=limit)}

    @app.get("/github-languages/by-language")
    def github_languages_by_language(
        name: str = Query(..., min_length=1),
        limit: int = Query(default=100, ge=1, le=500),
    ):
        return {
            "items": _require_languages_repo().query_by_language(
                language=name, limit=limit
            )
        }

    @app.get("/github-languages/{owner}/{repo}")
    def github_languages_by_repo(owner: str, repo: str):
        item = _require_languages_repo().query_by_repo(owner.lower(), repo.lower())
        if item is None:
            raise HTTPException(status_code=404, detail="not found")
        return item

    @app.post("/ops/github-languages/discover")
    def ops_github_languages_discover(
        channel: str = Query(default="cvelistv5"),
        since_iso: Optional[str] = Query(default=None),
        limit: Optional[int] = Query(default=None, ge=1),
    ):
        svc = _require_languages_service()
        if channel not in repositories:
            raise HTTPException(status_code=400, detail=f"unknown channel: {channel}")
        svc.raw_repo = repositories[channel]
        result = svc.discover_from_recent(
            channel=channel, since_iso=since_iso, limit=limit
        )
        return result.model_dump()

    @app.post("/ops/github-languages/sync")
    def ops_github_languages_sync(
        max_repos: int = Query(default=200, ge=1),
        max_seconds: int = Query(default=300, ge=1),
        priority: Optional[int] = Query(default=None, ge=0, le=1),
    ):
        result = _require_languages_service().run_worker(
            max_repos=max_repos,
            max_seconds=max_seconds,
            priority=priority,
        )
        return result.model_dump()

    return app
