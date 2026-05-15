"""DAO over the GitHub languages cache tables.

Schema is bootstrapped by :class:`SqliteRawRepository._init_db`; this class
is the canonical read/write surface for ``github_languages_cache`` and
``github_languages_data``.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from vulndb_mirror.crawler.github import RepoRef
from vulndb_mirror.storage.raw.raw_models import now_iso

logger = logging.getLogger(__name__)


@dataclass
class LanguagesQueueItem:
    owner: str
    repo: str
    priority: int
    languages_etag: Optional[str]


class GitHubLanguagesRepository:
    """SQLite-backed cache of GitHub repository language compositions."""

    def __init__(self, sqlite_path: str) -> None:
        self.sqlite_path = sqlite_path
        Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def enqueue_many(
        self, refs: Iterable[RepoRef], *, source_cve: Optional[str] = None
    ) -> int:
        """Upsert pending rows; merge ``source_cves``; raise priority to 0
        when a ``patch_url`` discovery promotes a previously ref-only row.

        Returns the number of (owner, repo) pairs touched.
        """
        items = list(refs)
        if not items:
            return 0
        ts = now_iso()
        touched = 0
        with self._connect() as conn:
            for ref in items:
                row = conn.execute(
                    "SELECT priority, source_cves, status FROM github_languages_cache "
                    "WHERE owner=? AND repo=?",
                    (ref.owner, ref.repo),
                ).fetchone()
                if row is None:
                    source = json.dumps([source_cve]) if source_cve else "[]"
                    conn.execute(
                        """
                        INSERT INTO github_languages_cache(
                            owner, repo, status, priority, source_cves,
                            enqueued_at, updated_at
                        ) VALUES(?, ?, 'pending', ?, ?, ?, ?)
                        """,
                        (ref.owner, ref.repo, ref.priority, source, ts, ts),
                    )
                    touched += 1
                    continue

                try:
                    existing = json.loads(row["source_cves"] or "[]")
                    if not isinstance(existing, list):
                        existing = []
                except (TypeError, ValueError):
                    existing = []
                if source_cve and source_cve not in existing:
                    existing.append(source_cve)
                new_priority = min(int(row["priority"]), int(ref.priority))
                current_status = row["status"]
                new_status = (
                    "pending"
                    if current_status in ("fetched", "not_modified")
                    else current_status
                )
                conn.execute(
                    """
                    UPDATE github_languages_cache
                    SET priority=?, source_cves=?, status=?, updated_at=?
                    WHERE owner=? AND repo=?
                    """,
                    (new_priority, json.dumps(existing), new_status, ts, ref.owner, ref.repo),
                )
                touched += 1
            conn.commit()
        return touched

    # ------------------------------------------------------------------
    # Queue dequeue
    # ------------------------------------------------------------------

    def next_batch(
        self,
        limit: int,
        *,
        priority: Optional[int] = None,
    ) -> list[LanguagesQueueItem]:
        """Pick up to *limit* pending rows in (priority ASC, enqueued_at ASC) order."""
        clauses = ["status = 'pending'"]
        args: list[object] = []
        if priority is not None:
            clauses.append("priority = ?")
            args.append(int(priority))

        sql = (
            "SELECT owner, repo, priority, languages_etag "
            "FROM github_languages_cache "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY priority ASC, enqueued_at ASC "
            "LIMIT ?"
        )
        args.append(int(limit))
        with self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [
            LanguagesQueueItem(
                owner=row["owner"],
                repo=row["repo"],
                priority=int(row["priority"]),
                languages_etag=row["languages_etag"],
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def upsert_languages(
        self,
        owner: str,
        repo: str,
        *,
        payload: dict,
        etag: Optional[str],
        http_status: int,
    ) -> None:
        """Persist a freshly fetched languages payload."""
        ts = now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE github_languages_cache
                SET status='fetched',
                    http_status=?,
                    error_message=NULL,
                    languages_etag=?,
                    fetched_at=?,
                    updated_at=?
                WHERE owner=? AND repo=?
                """,
                (http_status, etag, ts, ts, owner, repo),
            )
            conn.execute(
                "DELETE FROM github_languages_data WHERE owner=? AND repo=?",
                (owner, repo),
            )
            if payload:
                conn.executemany(
                    """
                    INSERT INTO github_languages_data(owner, repo, language, bytes)
                    VALUES(?, ?, ?, ?)
                    """,
                    [
                        (owner, repo, lang, bytes_count)
                        for lang, bytes_count in payload.items()
                        if isinstance(bytes_count, int)
                    ],
                )
            conn.commit()

    def touch_not_modified(self, owner: str, repo: str) -> None:
        """304 path: keep language data, just record the fetch time."""
        ts = now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE github_languages_cache
                SET status='fetched',
                    http_status=304,
                    error_message=NULL,
                    fetched_at=?,
                    updated_at=?
                WHERE owner=? AND repo=?
                """,
                (ts, ts, owner, repo),
            )
            conn.commit()

    def mark_status(
        self,
        owner: str,
        repo: str,
        *,
        status: str,
        http_status: Optional[int],
        error: Optional[str],
    ) -> None:
        ts = now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE github_languages_cache
                SET status=?, http_status=?, error_message=?, updated_at=?
                WHERE owner=? AND repo=?
                """,
                (status, http_status, error, ts, owner, repo),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def query_by_repo(self, owner: str, repo: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM github_languages_cache WHERE owner=? AND repo=?",
                (owner, repo),
            ).fetchone()
            if row is None:
                return None
            langs = conn.execute(
                "SELECT language, bytes FROM github_languages_data "
                "WHERE owner=? AND repo=? ORDER BY bytes DESC",
                (owner, repo),
            ).fetchall()
        return _row_to_repo_dict(row, langs)

    def query_by_language(
        self, language: str, *, limit: int = 100
    ) -> list[dict]:
        sql = (
            "SELECT d.owner, d.repo, d.language, d.bytes, "
            "       c.priority, c.source_cves, c.fetched_at "
            "FROM github_languages_data AS d "
            "JOIN github_languages_cache AS c "
            "  ON c.owner = d.owner AND c.repo = d.repo "
            "WHERE d.language = ? "
            "ORDER BY d.bytes DESC, c.priority ASC "
            "LIMIT ?"
        )
        with self._connect() as conn:
            rows = conn.execute(sql, (language, int(limit))).fetchall()
        results: list[dict] = []
        for row in rows:
            try:
                source_cves = json.loads(row["source_cves"] or "[]")
            except (TypeError, ValueError):
                source_cves = []
            results.append(
                {
                    "owner": row["owner"],
                    "repo": row["repo"],
                    "language": row["language"],
                    "bytes": int(row["bytes"]),
                    "priority": int(row["priority"]),
                    "source_cves": source_cves,
                    "fetched_at": row["fetched_at"],
                }
            )
        return results

    def stats(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(1) AS c FROM github_languages_cache GROUP BY status"
            ).fetchall()
            lang_total = conn.execute(
                "SELECT COUNT(1) AS c FROM github_languages_data"
            ).fetchone()["c"]
            pending_by_priority = conn.execute(
                "SELECT priority, COUNT(1) AS c FROM github_languages_cache "
                "WHERE status='pending' GROUP BY priority"
            ).fetchall()
        out: dict = {row["status"]: int(row["c"]) for row in rows}
        out["total_language_rows"] = int(lang_total)
        out["pending_by_priority"] = {
            int(row["priority"]): int(row["c"]) for row in pending_by_priority
        }
        return out


def _row_to_repo_dict(row: sqlite3.Row, langs: list[sqlite3.Row]) -> dict:
    try:
        source_cves = json.loads(row["source_cves"] or "[]")
    except (TypeError, ValueError):
        source_cves = []
    total_bytes = sum(int(r["bytes"]) for r in langs)
    languages = []
    for r in langs:
        b = int(r["bytes"])
        languages.append(
            {
                "language": r["language"],
                "bytes": b,
                "percent": round(b / total_bytes * 100, 2) if total_bytes else 0.0,
            }
        )
    return {
        "owner": row["owner"],
        "repo": row["repo"],
        "status": row["status"],
        "priority": int(row["priority"]),
        "http_status": row["http_status"],
        "error_message": row["error_message"],
        "source_cves": source_cves,
        "enqueued_at": row["enqueued_at"],
        "fetched_at": row["fetched_at"],
        "updated_at": row["updated_at"],
        "etag": row["languages_etag"],
        "languages": languages,
    }


__all__ = ["GitHubLanguagesRepository", "LanguagesQueueItem"]
