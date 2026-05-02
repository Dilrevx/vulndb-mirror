"""CVEProject/cvelistV5 ingest service.

Manages syncing the cvelistV5 Git repo (shallow clone) and ingesting
CVE JSON 5.0 files into the raw repository.  State is persisted in
``.cvelistv5_state.json`` inside the configured ``data_dir``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.crawler.cvelistv5 import CvelistV5Crawler
from vulndb_mirror.storage.raw_models import now_iso
from vulndb_mirror.storage.repositories import RawRepository

logger = logging.getLogger(__name__)

_STATE_FILE = ".cvelistv5_state.json"


class CvelistV5SyncResult(BaseModel):
    """Result of a single cvelistV5 sync run."""

    saved_entries: int = Field(default=0, ge=0)
    commit: Optional[str] = None
    previous_commit: Optional[str] = None
    already_up_to_date: bool = False
    error: Optional[str] = None
    synced_at: str = Field(default_factory=now_iso)


class CvelistV5IngestService:
    """Sync the CVEProject/cvelistV5 repo and ingest CVE entries."""

    def __init__(self, config: CrawlConfig, repository: RawRepository) -> None:
        self.config = config
        self.repository = repository
        self._crawler = CvelistV5Crawler(config)
        self._state_path = Path(config.data_dir) / _STATE_FILE

    def sync(self, *, full: bool = False) -> CvelistV5SyncResult:
        prev_commit, _ = self._load_state()
        since_commit = None if (full or prev_commit is None) else prev_commit

        logger.info(
            "Starting cvelistV5 sync (full=%s, since_commit=%s)",
            full, since_commit,
        )

        try:
            new_commit = self._crawler.sync_repo()
        except Exception as exc:
            msg = str(exc)
            logger.error("Failed to sync cvelistV5 repo: %s", msg)
            return CvelistV5SyncResult(error=msg)

        if since_commit and since_commit == new_commit:
            logger.info("Already up-to-date at commit %s", new_commit)
            return CvelistV5SyncResult(
                commit=new_commit,
                previous_commit=prev_commit,
                already_up_to_date=True,
            )

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
            if saved % 5000 == 0:
                logger.info("Ingested %d entries…", saved)

        self._save_state(new_commit, now_iso())
        logger.info(
            "cvelistV5 sync complete: %d entries saved (commit=%s)",
            saved, new_commit,
        )

        return CvelistV5SyncResult(
            saved_entries=saved,
            commit=new_commit,
            previous_commit=prev_commit,
        )

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
