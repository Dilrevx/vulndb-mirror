from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from vulndb_mirror.storage.ingest_service import RawIngestService
from vulndb_mirror.storage.raw_models import RetryRequest
from vulndb_mirror.storage.repositories import RawRepository


def create_app(
    repositories: dict[str, RawRepository],
    services: dict[str, Any],
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

    return app
