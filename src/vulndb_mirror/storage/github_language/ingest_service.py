"""Orchestrator for the GitHub languages cache.

Two phases:

* :meth:`GithubLanguagesIngestService.discover_from_recent` — pure DB pass
  over ``raw_entries`` to extract GitHub repos and enqueue them.
* :meth:`GithubLanguagesIngestService.run_worker` — drain the queue with
  bounded concurrency, respecting GitHub rate limits.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Optional

from pydantic import BaseModel, Field

from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.crawler.github.languages import GitHubLanguagesCrawler, LanguagesResult
from vulndb_mirror.crawler.github import RepoRef, extract_repo_refs
from vulndb_mirror.models import RawAVDEntry
from vulndb_mirror.storage.github_language.repository import (
    GitHubLanguagesRepository,
    LanguagesQueueItem,
)
from vulndb_mirror.storage.raw.raw_models import now_iso
from vulndb_mirror.storage.raw.repositories import RawRepository, SqliteRawRepository

logger = logging.getLogger(__name__)


class DiscoverResult(BaseModel):
    cves_scanned: int = Field(default=0, ge=0)
    repos_seen: int = Field(default=0, ge=0)
    repos_enqueued: int = Field(default=0, ge=0)
    repos_patch: int = Field(default=0, ge=0)
    repos_ref: int = Field(default=0, ge=0)
    channel: Optional[str] = None
    since_iso: Optional[str] = None
    finished_at: str = Field(default_factory=now_iso)


class WorkerResult(BaseModel):
    processed: int = Field(default=0, ge=0)
    fetched: int = Field(default=0, ge=0)
    not_modified: int = Field(default=0, ge=0)
    skipped_404: int = Field(default=0, ge=0)
    skipped_403: int = Field(default=0, ge=0)
    errors: int = Field(default=0, ge=0)
    elapsed_seconds: float = 0.0
    stopped_reason: str = "queue_empty"
    finished_at: str = Field(default_factory=now_iso)


class _HourlyTokenBucket:
    """Strict hourly cap; sleeps the calling thread when the cap is reached."""

    def __init__(self, capacity: int) -> None:
        self._capacity = max(1, int(capacity))
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self, deadline: Optional[float] = None, stop: Optional[threading.Event] = None) -> bool:
        """Block until a slot is free; return False if *deadline* would be missed or *stop* is set."""
        while True:
            with self._lock:
                now = time.time()
                while self._stamps and now - self._stamps[0] > 3600:
                    self._stamps.popleft()
                if len(self._stamps) < self._capacity:
                    self._stamps.append(now)
                    return True
                wait = 3600 - (now - self._stamps[0]) + 0.1
            if deadline is not None and time.time() + wait > deadline:
                return False
            if stop is not None and stop.is_set():
                return False
            logger.info(
                "Languages hourly budget reached (%d/h); sleeping %.0fs",
                self._capacity,
                wait,
            )
            chunk = min(wait, 30)
            if stop is not None:
                stop.wait(chunk)
            else:
                time.sleep(chunk)


class GithubLanguagesIngestService:
    """High-level wrapper that ties discovery + worker together."""

    def __init__(
        self,
        settings: CrawlerSettings,
        raw_repo: RawRepository,
        languages_repo: GitHubLanguagesRepository,
        crawler: GitHubLanguagesCrawler,
    ) -> None:
        self.settings = settings
        self.raw_repo = raw_repo
        self.languages_repo = languages_repo
        self.crawler = crawler

    # ------------------------------------------------------------------
    # Phase 1: discover (DB-only)
    # ------------------------------------------------------------------

    def discover_from_recent(
        self,
        *,
        channel: Optional[str] = None,
        since_iso: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> DiscoverResult:
        """Scan recently-updated CVE rows; enqueue every GitHub repo found."""
        rows_iter = _iter_raw_payloads(
            self.raw_repo, since_iso=since_iso, limit=limit
        )

        cves_scanned = 0
        repos_seen = 0
        repos_enqueued = 0
        repos_patch = 0
        repos_ref = 0
        for cve_id, payload in rows_iter:
            cves_scanned += 1
            try:
                entry = RawAVDEntry.model_validate_json(payload)
            except Exception:
                continue
            refs = extract_repo_refs(entry.references, entry.patch_urls)
            if not refs:
                continue
            repos_seen += len(refs)
            repos_patch += sum(1 for r in refs if r.priority == 0)
            repos_ref += sum(1 for r in refs if r.priority == 1)
            repos_enqueued += self.languages_repo.enqueue_many(
                refs, source_cve=cve_id
            )

        logger.info(
            "Languages discover: scanned=%d, repos_seen=%d, enqueued=%d, patch=%d, ref=%d (channel=%s)",
            cves_scanned,
            repos_seen,
            repos_enqueued,
            repos_patch,
            repos_ref,
            channel,
        )
        return DiscoverResult(
            cves_scanned=cves_scanned,
            repos_seen=repos_seen,
            repos_enqueued=repos_enqueued,
            repos_patch=repos_patch,
            repos_ref=repos_ref,
            channel=channel,
            since_iso=since_iso,
        )

    # ------------------------------------------------------------------
    # Phase 2: drain queue (network)
    # ------------------------------------------------------------------

    def run_worker(
        self,
        *,
        max_repos: int,
        max_seconds: int,
        concurrency: Optional[int] = None,
        priority: Optional[int] = None,
    ) -> WorkerResult:
        """Drain pending rows until budget exhausted."""
        thread_count = max(1, int(concurrency or self.settings.github_languages_concurrency))
        bucket = _HourlyTokenBucket(self.settings.github_languages_hourly_budget)

        deadline = time.time() + max(1, int(max_seconds))
        result = WorkerResult()
        start = time.time()
        remaining = max(0, int(max_repos))
        stopped_reason = "queue_empty"

        with ThreadPoolExecutor(max_workers=thread_count) as pool:
            while remaining > 0 and time.time() < deadline:
                batch_size = min(remaining, max(thread_count * 2, 8))
                batch = self.languages_repo.next_batch(
                    batch_size, priority=priority
                )
                if not batch:
                    stopped_reason = "queue_empty"
                    break

                if not bucket.acquire(deadline=deadline):
                    stopped_reason = "rate_limit"
                    break

                reserved = [batch[0]]
                for item in batch[1:]:
                    if time.time() >= deadline:
                        break
                    if not bucket.acquire(deadline=deadline):
                        stopped_reason = "rate_limit"
                        break
                    reserved.append(item)

                futures = {
                    pool.submit(self._process_one, item): item
                    for item in reserved
                }
                for fut in as_completed(futures):
                    item = futures[fut]
                    try:
                        outcome = fut.result()
                    except Exception as exc:
                        logger.warning(
                            "Languages worker exception for %s/%s: %s",
                            item.owner,
                            item.repo,
                            exc,
                        )
                        self.languages_repo.mark_status(
                            item.owner,
                            item.repo,
                            status="error",
                            http_status=None,
                            error=str(exc),
                        )
                        result.errors += 1
                    else:
                        _accumulate(result, outcome)
                    result.processed += 1
                    remaining -= 1

                if stopped_reason == "rate_limit":
                    break
                if time.time() >= deadline:
                    stopped_reason = "deadline"
                    break

        if remaining <= 0 and stopped_reason == "queue_empty":
            stopped_reason = "max_repos"
        result.elapsed_seconds = round(time.time() - start, 3)
        result.stopped_reason = stopped_reason
        result.finished_at = now_iso()
        logger.info(
            "Languages worker done: processed=%d fetched=%d not_modified=%d "
            "skip_404=%d skip_403=%d errors=%d elapsed=%.2fs reason=%s",
            result.processed,
            result.fetched,
            result.not_modified,
            result.skipped_404,
            result.skipped_403,
            result.errors,
            result.elapsed_seconds,
            stopped_reason,
        )
        return result

    # ------------------------------------------------------------------
    # Long-running service
    # ------------------------------------------------------------------

    def run_service(
        self,
        *,
        raw_repos: dict[str, RawRepository],
        priority: Optional[int] = None,
        discover_interval_seconds: int = 3600,
    ) -> None:
        """Blocking service loop. Runs until SIGINT/SIGTERM."""
        stop = threading.Event()

        def _on_signal(sig: int, _frame: object) -> None:
            logger.info("Languages service: signal %d received, stopping after current batch", sig)
            stop.set()

        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)

        thread_count = max(1, int(self.settings.github_languages_concurrency))
        bucket = _HourlyTokenBucket(self.settings.github_languages_hourly_budget)

        last_discover_at: float = 0.0
        full_discover_done = False
        total_processed = 0

        logger.info(
            "Languages service started: channels=%s priority=%s interval=%ds",
            list(raw_repos),
            priority,
            discover_interval_seconds,
        )

        with ThreadPoolExecutor(max_workers=thread_count) as pool:
            while not stop.is_set():
                now = time.time()

                if now - last_discover_at >= discover_interval_seconds:
                    since_30d = (
                        datetime.utcnow() - timedelta(days=30)
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    for ch, repo in raw_repos.items():
                        self.raw_repo = repo
                        self.discover_from_recent(channel=ch, since_iso=since_30d)
                    last_discover_at = time.time()
                    full_discover_done = False

                batch = self.languages_repo.next_batch(
                    max(thread_count * 2, 8), priority=priority
                )

                if not batch:
                    if not full_discover_done:
                        logger.info("Languages service: recent queue empty, running full discover...")
                        for ch, repo in raw_repos.items():
                            self.raw_repo = repo
                            self.discover_from_recent(channel=ch, since_iso=None)
                        full_discover_done = True
                        continue
                    wait = max(10.0, discover_interval_seconds - (time.time() - last_discover_at))
                    logger.info(
                        "Languages service: queue empty, sleeping %.0fs until next discover", wait
                    )
                    stop.wait(min(wait, 60))
                    continue

                reserved = []
                for item in batch:
                    if stop.is_set():
                        break
                    if not bucket.acquire(stop=stop):
                        break
                    reserved.append(item)

                if not reserved:
                    continue

                futures = {
                    pool.submit(self._process_one, item): item
                    for item in reserved
                }
                for fut in as_completed(futures):
                    item = futures[fut]
                    try:
                        outcome = fut.result()
                        _accumulate_log(item, outcome)
                    except Exception as exc:
                        logger.warning("Languages %s/%s error: %s", item.owner, item.repo, exc)
                        self.languages_repo.mark_status(
                            item.owner, item.repo,
                            status="error", http_status=None, error=str(exc),
                        )
                    total_processed += 1
                    if total_processed % 100 == 0:
                        logger.info("Languages service: total_processed=%d", total_processed)

        logger.info("Languages service stopped. total_processed=%d", total_processed)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _process_one(self, item: LanguagesQueueItem) -> LanguagesResult:
        result = self.crawler.fetch_languages(
            item.owner, item.repo, etag=item.languages_etag
        )
        if result.status == "fetched" and result.payload is not None:
            self.languages_repo.upsert_languages(
                item.owner,
                item.repo,
                payload=result.payload,
                etag=result.etag,
                http_status=result.http_status or 200,
            )
        elif result.status == "not_modified":
            self.languages_repo.touch_not_modified(item.owner, item.repo)
        else:
            self.languages_repo.mark_status(
                item.owner,
                item.repo,
                status=result.status,
                http_status=result.http_status,
                error=result.error,
            )
        return result


def _accumulate(acc: WorkerResult, outcome: LanguagesResult) -> None:
    if outcome.status == "fetched":
        acc.fetched += 1
    elif outcome.status == "not_modified":
        acc.not_modified += 1
    elif outcome.status == "skip_404":
        acc.skipped_404 += 1
    elif outcome.status == "skip_403":
        acc.skipped_403 += 1
    else:
        acc.errors += 1


def _accumulate_log(item: LanguagesQueueItem, outcome: LanguagesResult) -> None:
    if outcome.status not in ("fetched", "not_modified"):
        logger.debug("Languages %s/%s → %s", item.owner, item.repo, outcome.status)


def _iter_raw_payloads(
    raw_repo: RawRepository,
    *,
    since_iso: Optional[str],
    limit: Optional[int],
):
    sqlite_repo = _resolve_sqlite_repo(raw_repo)
    if sqlite_repo is not None:
        clauses: list[str] = []
        args: list[object] = []
        if since_iso:
            clauses.append("updated_at >= ?")
            args.append(since_iso)
        sql = "SELECT cve_id, payload FROM raw_entries"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(int(limit))
        with sqlite_repo._connect() as conn:  # noqa: SLF001
            rows = conn.execute(sql, args).fetchall()
        for row in rows:
            yield row["cve_id"], row["payload"]
        return

    cve_ids = raw_repo.list_cve_ids()
    if limit is not None:
        cve_ids = cve_ids[: int(limit)]
    for cve_id in cve_ids:
        entry = raw_repo.get_raw(cve_id)
        if entry is None:
            continue
        yield cve_id, entry.model_dump_json()


def _resolve_sqlite_repo(raw_repo: RawRepository) -> Optional[SqliteRawRepository]:
    if isinstance(raw_repo, SqliteRawRepository):
        return raw_repo
    primary = getattr(raw_repo, "primary", None)
    if isinstance(primary, SqliteRawRepository):
        return primary
    secondary = getattr(raw_repo, "secondary", None)
    if isinstance(secondary, SqliteRawRepository):
        return secondary
    return None


__all__ = [
    "GithubLanguagesIngestService",
    "DiscoverResult",
    "WorkerResult",
]
