from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from pydantic import BaseModel, Field

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.crawler.ghsa.advisory_db import GhsaAdvisoryDbCrawler
from .repository import GhsaRepository

logger = logging.getLogger(__name__)

_STATE_FILE = ".ghsa_state.json"


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class GhsaSyncResult(BaseModel):
    saved_entries: int = Field(default=0, ge=0)
    commit: Optional[str] = None
    previous_commit: Optional[str] = None
    already_up_to_date: bool = False
    error: Optional[str] = None
    synced_at: str = Field(default_factory=_now_iso)


class GhsaIngestService:
    def __init__(
        self,
        config: CrawlConfig,
        repository: GhsaRepository,
        *,
        on_sync_complete: Optional[Callable[[GhsaSyncResult], None]] = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self._crawler = GhsaAdvisoryDbCrawler(config)
        self._state_path = Path(config.data_dir) / _STATE_FILE
        self._on_sync_complete = on_sync_complete

    def sync(self, *, full: bool = False) -> GhsaSyncResult:
        prev_commit, _ = self._load_state()
        since_commit = None if (full or prev_commit is None) else prev_commit

        logger.info(
            "Starting GHSA sync (full=%s, since_commit=%s)",
            full, since_commit,
        )

        try:
            new_commit = self._crawler.sync_repo()
        except Exception as exc:
            msg = str(exc)
            logger.error("Failed to sync advisory-database repo: %s", msg)
            return GhsaSyncResult(error=msg)

        if since_commit and since_commit == new_commit:
            logger.info("Already up-to-date at commit %s", new_commit)
            result = GhsaSyncResult(
                commit=new_commit,
                previous_commit=prev_commit,
                already_up_to_date=True,
            )
            self._fire_hook(result)
            return result

        saved = 0
        for entry in self._crawler.iter_entries(since_commit=since_commit):
            self.repository.upsert(entry)
            saved += 1
            if saved % 5000 == 0:
                logger.info("Ingested %d GHSA entries…", saved)

        synced_at = _now_iso()
        self._save_state(new_commit, synced_at)
        logger.info(
            "GHSA sync complete: %d entries saved (commit=%s)",
            saved, new_commit,
        )

        result = GhsaSyncResult(
            saved_entries=saved,
            commit=new_commit,
            previous_commit=prev_commit,
            synced_at=synced_at,
        )
        self._fire_hook(result)
        return result

    def _fire_hook(self, result: GhsaSyncResult) -> None:
        if self._on_sync_complete is None:
            return
        try:
            self._on_sync_complete(result)
        except Exception as exc:
            logger.warning("GHSA on_sync_complete hook failed: %s", exc)

    def _load_state(self) -> tuple[Optional[str], Optional[str]]:
        if self._state_path.exists():
            try:
                data = json.loads(self._state_path.read_text(encoding="utf-8"))
                return data.get("last_commit"), data.get("last_sync")
            except Exception:
                pass
        return None, None

    def _save_state(self, commit: str, synced_at: str) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(
            json.dumps({"last_commit": commit, "last_sync": synced_at}, indent=2),
            encoding="utf-8",
        )
