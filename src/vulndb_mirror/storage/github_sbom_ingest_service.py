"""Orchestrator for the GitHub SBOM cache.

Two phases:

* :meth:`GithubSbomIngestService.discover_from_recent` — pure DB pass over
  ``raw_entries`` to extract GitHub repos and enqueue them.
* :meth:`GithubSbomIngestService.run_worker` — drain the queue with bounded
  concurrency, respecting GitHub rate limits.
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
from vulndb_mirror.crawler.github_sbom import (
    GitHubSbomCrawler,
    RepoRef,
    SbomResult,
)
from vulndb_mirror.models import RawAVDEntry
from vulndb_mirror.storage.github_sbom_repository import (
    GitHubSbomRepository,
    SbomQueueItem,
)
from vulndb_mirror.storage.raw_models import now_iso
from vulndb_mirror.storage.repositories import RawRepository, SqliteRawRepository

logger = logging.getLogger(__name__)


class DiscoverResult(BaseModel):
    cves_scanned: int = Field(default=0, ge=0)
    repos_seen: int = Field(default=0, ge=0)
    repos_enqueued: int = Field(default=0, ge=0)
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
                "SBOM hourly budget reached (%d/h); sleeping %.0fs",
                self._capacity,
                wait,
            )
            chunk = min(wait, 30)
            if stop is not None:
                stop.wait(chunk)
            else:
                time.sleep(chunk)


class GithubSbomIngestService:
    """High-level wrapper that ties discovery + worker together."""

    def __init__(
        self,
        settings: CrawlerSettings,
        raw_repo: RawRepository,
        sbom_repo: GitHubSbomRepository,
        crawler: GitHubSbomCrawler,
    ) -> None:
        self.settings = settings
        self.raw_repo = raw_repo
        self.sbom_repo = sbom_repo
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
        """Scan recently-updated CVE rows; enqueue every GitHub repo found.

        *since_iso* should be the previous sync timestamp (channels persist
        this in their state file). When omitted, every row is scanned.
        """
        rows_iter = _iter_raw_payloads(
            self.raw_repo, since_iso=since_iso, limit=limit
        )

        cves_scanned = 0
        repos_seen = 0
        repos_enqueued = 0
        for cve_id, payload in rows_iter:
            cves_scanned += 1
            try:
                entry = RawAVDEntry.model_validate_json(payload)
            except Exception:
                continue
            refs = self.crawler.extract_repo_refs(
                entry.references, entry.patch_urls
            )
            if not refs:
                continue
            repos_seen += len(refs)
            repos_enqueued += self.sbom_repo.enqueue_many(
                refs, source_cve=cve_id
            )

        logger.info(
            "SBOM discover: scanned=%d, repos_seen=%d, enqueued=%d (channel=%s)",
            cves_scanned,
            repos_seen,
            repos_enqueued,
            channel,
        )
        return DiscoverResult(
            cves_scanned=cves_scanned,
            repos_seen=repos_seen,
            repos_enqueued=repos_enqueued,
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
        thread_count = max(1, int(concurrency or self.settings.github_sbom_concurrency))
        bucket = _HourlyTokenBucket(self.settings.github_sbom_hourly_budget)

        deadline = time.time() + max(1, int(max_seconds))
        result = WorkerResult()
        start = time.time()
        remaining = max(0, int(max_repos))
        stopped_reason = "queue_empty"

        with ThreadPoolExecutor(max_workers=thread_count) as pool:
            while remaining > 0 and time.time() < deadline:
                batch_size = min(remaining, max(thread_count * 2, 8))
                batch = self.sbom_repo.next_batch(
                    batch_size, priority=priority
                )
                if not batch:
                    stopped_reason = "queue_empty"
                    break

                if not bucket.acquire(deadline=deadline):
                    stopped_reason = "rate_limit"
                    break

                # First slot already consumed for the head item; reserve the rest.
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
                            "SBOM worker exception for %s/%s: %s",
                            item.owner,
                            item.repo,
                            exc,
                        )
                        self.sbom_repo.mark_status(
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
            "SBOM worker done: processed=%d fetched=%d not_modified=%d "
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
        """Blocking service loop. Runs until SIGINT/SIGTERM.

        Each cycle:
        1. Discover repos from the last 30 days across all *raw_repos* channels.
        2. Drain the queue (respecting hourly budget; sleeps when rate-limited).
        3. When queue empties, do a full discover (no time filter) to catch
           older CVEs, then drain again.
        4. Sleep until the next discover interval, then repeat.
        """
        stop = threading.Event()

        def _on_signal(sig: int, _frame: object) -> None:
            logger.info("SBOM service: signal %d received, stopping after current batch", sig)
            stop.set()

        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)

        thread_count = max(1, int(self.settings.github_sbom_concurrency))

        last_discover_at: float = 0.0
        full_discover_done = False
        total_processed = 0

        logger.info(
            "SBOM service started: channels=%s priority=%s interval=%ds",
            list(raw_repos),
            priority,
            discover_interval_seconds,
        )

        with ThreadPoolExecutor(max_workers=thread_count) as pool:
            while not stop.is_set():
                now = time.time()

                # Periodic discover: recent 30 days
                if now - last_discover_at >= discover_interval_seconds:
                    since_30d = (
                        datetime.utcnow() - timedelta(days=30)
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    for ch, repo in raw_repos.items():
                        self.raw_repo = repo
                        self.discover_from_recent(channel=ch, since_iso=since_30d)
                    last_discover_at = time.time()
                    full_discover_done = False

                # Pull next batch
                batch = self.sbom_repo.next_batch(
                    max(thread_count * 2, 8), priority=priority
                )

                if not batch:
                    if not full_discover_done:
                        logger.info("SBOM service: recent queue empty, running full discover...")
                        for ch, repo in raw_repos.items():
                            self.raw_repo = repo
                            self.discover_from_recent(channel=ch, since_iso=None)
                        full_discover_done = True
                        continue
                    wait = max(10.0, discover_interval_seconds - (time.time() - last_discover_at))
                    logger.info(
                        "SBOM service: queue empty, sleeping %.0fs until next discover", wait
                    )
                    stop.wait(min(wait, 60))
                    continue

                # Acquire rate-limit tokens for each item in the batch
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
                        logger.warning("SBOM %s/%s error: %s", item.owner, item.repo, exc)
                        self.sbom_repo.mark_status(
                            item.owner, item.repo,
                            status="error", http_status=None, error=str(exc),
                        )
                    total_processed += 1
                    if total_processed % 100 == 0:
                        logger.info("SBOM service: total_processed=%d", total_processed)

        logger.info("SBOM service stopped. total_processed=%d", total_processed)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _process_one(self, item: SbomQueueItem) -> SbomResult:
        result = self.crawler.fetch_sbom(
            item.owner, item.repo, etag=item.sbom_etag
        )
        if result.status == "fetched" and result.payload is not None:
            packages = self.crawler.parse_sbom(result.payload)
            self.sbom_repo.upsert_sbom(
                item.owner,
                item.repo,
                payload=result.payload,
                packages=packages,
                etag=result.etag,
                http_status=result.http_status or 200,
            )
        elif result.status == "not_modified":
            self.sbom_repo.touch_not_modified(item.owner, item.repo)
        else:
            self.sbom_repo.mark_status(
                item.owner,
                item.repo,
                status=result.status,
                http_status=result.http_status,
                error=result.error,
            )
        return result


def _accumulate(acc: WorkerResult, outcome: SbomResult) -> None:
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


def _accumulate_log(item: SbomQueueItem, outcome: SbomResult) -> None:
    if outcome.status not in ("fetched", "not_modified"):
        logger.debug("SBOM %s/%s → %s", item.owner, item.repo, outcome.status)


def _iter_raw_payloads(
    raw_repo: RawRepository,
    *,
    since_iso: Optional[str],
    limit: Optional[int],
):
    """Stream ``(cve_id, payload_json)`` rows from the underlying SQLite store.

    Uses :class:`SqliteRawRepository`'s own connection helper when available,
    falling back to scanning ``list_cve_ids`` + ``get_raw`` (slower but works
    for any :class:`RawRepository` implementation).
    """
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
        with sqlite_repo._connect() as conn:  # noqa: SLF001 — same package
            # Fully materialise so the read connection closes before the
            # caller starts issuing writes (sqlite default journal locks
            # the file otherwise).
            rows = conn.execute(sql, args).fetchall()
        for row in rows:
            yield row["cve_id"], row["payload"]
        return

    # Fallback: full enumeration via the abstract interface.
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
    "GithubSbomIngestService",
    "DiscoverResult",
    "WorkerResult",
]
