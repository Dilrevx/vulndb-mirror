"""Trickest CVE ingest service.

Manages syncing the trickest/cve Git repo and ingesting CVE markdown files
into the raw repository.  State is persisted in ``.trickest_state.json``
inside the configured ``data_dir``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Optional

from pydantic import BaseModel, Field

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.crawler.trickest import TrickestCrawler
from .raw_models import now_iso
from .repositories import RawRepository

logger = logging.getLogger(__name__)

_STATE_FILE = ".trickest_state.json"


class TrickestSyncResult(BaseModel):
    """Result of a single trickest sync run."""

    saved_entries: int = Field(default=0, ge=0)
    commit: Optional[str] = None
    previous_commit: Optional[str] = None
    already_up_to_date: bool = False
    error: Optional[str] = None
    synced_at: str = Field(default_factory=now_iso)
    last_sync_iso: Optional[str] = None


class TrickestIngestService:
    """Sync the trickest/cve repository and ingest CVE entries into storage."""

    def __init__(
        self,
        config: CrawlConfig,
        repository: RawRepository,
        *,
        on_sync_complete: Optional[
            Callable[["TrickestSyncResult"], None]
        ] = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self._crawler = TrickestCrawler(config)
        self._state_path = Path(config.data_dir) / _STATE_FILE
        self._on_sync_complete = on_sync_complete

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sync(self, *, full: bool = False) -> TrickestSyncResult:
        """Clone or pull the trickest/cve repo and ingest changed entries.

        Args:
            full: When ``True``, re-process all CVE files regardless of the
                  last-synced commit (useful for initial load or repairs).
        """
        prev_commit, prev_sync_iso = self._load_state()
        since_commit = None if (full or prev_commit is None) else prev_commit

        logger.info(
            "Starting trickest sync (full=%s, since_commit=%s)",
            full,
            since_commit,
        )

        try:
            new_commit = self._crawler.sync_repo()
        except Exception as exc:
            msg = str(exc)
            logger.error("Failed to sync trickest/cve repo: %s", msg)
            return TrickestSyncResult(error=msg)

        if since_commit and since_commit == new_commit:
            logger.info("Already up-to-date at commit %s", new_commit)
            result = TrickestSyncResult(
                commit=new_commit,
                previous_commit=prev_commit,
                already_up_to_date=True,
                last_sync_iso=prev_sync_iso,
            )
            self._fire_hook(result)
            return result

        since_year: Optional[int] = None
        if self.config.since:
            try:
                since_year = int(self.config.since[:4])
            except (ValueError, IndexError):
                pass

        saved = 0
        for entry in self._crawler.iter_entries(
            since_commit=since_commit,
            since_year=since_year,
        ):
            self.repository.upsert_raw(entry, page=1)
            saved += 1
            if saved % 1000 == 0:
                logger.info("Ingested %d entries…", saved)

        synced_at = now_iso()
        self._save_state(new_commit, synced_at)
        logger.info(
            "Trickest sync complete: %d entries saved (commit=%s)", saved, new_commit
        )

        result = TrickestSyncResult(
            saved_entries=saved,
            commit=new_commit,
            previous_commit=prev_commit,
            synced_at=synced_at,
            last_sync_iso=prev_sync_iso,
        )
        self._fire_hook(result)
        return result

    def _fire_hook(self, result: TrickestSyncResult) -> None:
        if self._on_sync_complete is None:
            return
        try:
            self._on_sync_complete(result)
        except Exception as exc:
            logger.warning("trickest on_sync_complete hook failed: %s", exc)

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

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
