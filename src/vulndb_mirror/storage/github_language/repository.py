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
from vulndb_mirror.storage.cve.models import now_iso

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
                current_status = row["status"]
                new_cve_added = bool(source_cve and source_cve not in existing)
                if new_cve_added:
                    existing.append(source_cve)
                new_priority = min(int(row["priority"]), int(ref.priority))

                if current_status in ("fetched", "not_modified", "error"):
                    new_status = "pending" if new_cve_added else current_status
                else:
                    new_status = current_status

                if new_status == "pending":
                    conn.execute(
                        """
                        UPDATE github_languages_cache
                        SET priority=?, source_cves=?, status=?,
                            enqueued_at=?, updated_at=?
                        WHERE owner=? AND repo=?
                        """,
                        (new_priority, json.dumps(existing), new_status,
                         ts, ts, ref.owner, ref.repo),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE github_languages_cache
                        SET priority=?, source_cves=?, status=?, updated_at=?
                        WHERE owner=? AND repo=?
                        """,
                        (new_priority, json.dumps(existing), new_status,
                         ts, ref.owner, ref.repo),
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
        self, language: str, *, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        sql = (
            "SELECT d.owner, d.repo, d.language, d.bytes, "
            "       c.priority, c.source_cves, c.fetched_at "
            "FROM github_languages_data AS d "
            "JOIN github_languages_cache AS c "
            "  ON c.owner = d.owner AND c.repo = d.repo "
            "WHERE d.language = ? "
            "ORDER BY d.bytes DESC, c.priority ASC "
            "LIMIT ? OFFSET ?"
        )
        with self._connect() as conn:
            rows = conn.execute(sql, (language, int(limit), int(offset))).fetchall()
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

    def top_languages(self, limit: int = 50) -> list[dict]:
        """Aggregate top languages by total bytes, with repo count,
        unique CVE count, and unique CWE count per language.

        Uses 2 batch queries instead of per-language N+1 lookups.
        """
        sql = (
            "SELECT d.language, "
            "       SUM(d.bytes) AS total_bytes, "
            "       COUNT(DISTINCT d.owner || '/' || d.repo) AS repo_count "
            "FROM github_languages_data AS d "
            "JOIN github_languages_cache AS c "
            "  ON c.owner = d.owner AND c.repo = d.repo "
            "GROUP BY d.language "
            "ORDER BY total_bytes DESC "
            "LIMIT ?"
        )
        with self._connect() as conn:
            rows = conn.execute(sql, (int(limit),)).fetchall()
            if not rows:
                return []

            top_langs = [row["language"] for row in rows]

            # Batch-1: collect all (language, source_cves) for top languages
            placeholders = ",".join("?" for _ in top_langs)
            cve_rows = conn.execute(
                f"SELECT d.language, c.source_cves "
                f"FROM github_languages_data AS d "
                f"JOIN github_languages_cache AS c "
                f"  ON c.owner = d.owner AND c.repo = d.repo "
                f"WHERE d.language IN ({placeholders})",
                tuple(top_langs),
            ).fetchall()

            lang_cves: dict[str, set[str]] = {lang: set() for lang in top_langs}
            all_cves: set[str] = set()
            for cr in cve_rows:
                try:
                    cve_list = json.loads(cr["source_cves"] or "[]")
                    if isinstance(cve_list, list):
                        lang_cves[cr["language"]].update(cve_list)
                        all_cves.update(cve_list)
                except (TypeError, ValueError):
                    pass

            # Batch-2: map all CVEs → CWE in one go
            cve_to_cwe: dict[str, str] = {}
            if all_cves:
                batch_size = 500
                cve_list = list(all_cves)
                for i in range(0, len(cve_list), batch_size):
                    batch = cve_list[i:i + batch_size]
                    bp = ",".join("?" for _ in batch)
                    raw_rows = conn.execute(
                        f"SELECT cve_id, json_extract(payload, '$.cwe_id') AS cwe_id "
                        f"FROM raw_entries "
                        f"WHERE cve_id IN ({bp}) "
                        f"  AND json_extract(payload, '$.cwe_id') IS NOT NULL "
                        f"  AND json_extract(payload, '$.cwe_id') != ''",
                        tuple(batch),
                    ).fetchall()
                    for rr in raw_rows:
                        if rr["cwe_id"]:
                            cve_to_cwe[rr["cve_id"]] = rr["cwe_id"]

            results = []
            for row in rows:
                lang = row["language"]
                cves = lang_cves.get(lang, set())
                unique_cwes = {cve_to_cwe[c] for c in cves if c in cve_to_cwe}
                results.append({
                    "language": lang,
                    "total_bytes": int(row["total_bytes"]),
                    "repo_count": int(row["repo_count"]),
                    "cve_count": len(cves),
                    "cwe_count": len(unique_cwes),
                })
        return results

    def cwe_language_stats(self, limit: int = 100) -> list[dict]:
        """For each CWE, aggregate language distribution across
        repos referenced by CVEs with that CWE type."""
        with self._connect() as conn:
            # Collect all languages data with their CVE references
            data_rows = conn.execute(
                "SELECT d.language, d.bytes, c.source_cves "
                "FROM github_languages_data AS d "
                "JOIN github_languages_cache AS c "
                "  ON c.owner = d.owner AND c.repo = d.repo"
            ).fetchall()

            # Build CVE → CWE map from raw_entries
            all_cves: set[str] = set()
            for dr in data_rows:
                try:
                    cve_list = json.loads(dr["source_cves"] or "[]")
                    if isinstance(cve_list, list):
                        all_cves.update(cve_list)
                except (TypeError, ValueError):
                    pass

            cve_to_cwe: dict[str, str] = {}
            cwe_to_desc: dict[str, str] = {}
            batch_size = 500
            cve_list = list(all_cves)
            for i in range(0, len(cve_list), batch_size):
                batch = cve_list[i:i + batch_size]
                placeholders = ",".join("?" for _ in batch)
                raw_rows = conn.execute(
                    f"SELECT cve_id, json_extract(payload, '$.cwe_id') AS cwe_id, "
                    f"       json_extract(payload, '$.cwe_description') AS cwe_description "
                    f"FROM raw_entries "
                    f"WHERE cve_id IN ({placeholders}) "
                    f"  AND json_extract(payload, '$.cwe_id') IS NOT NULL "
                    f"  AND json_extract(payload, '$.cwe_id') != ''",
                    tuple(batch),
                ).fetchall()
                for rr in raw_rows:
                    if rr["cwe_id"]:
                        cve_to_cwe[rr["cve_id"]] = rr["cwe_id"]
                        if rr["cwe_description"] and rr["cwe_id"] not in cwe_to_desc:
                            cwe_to_desc[rr["cwe_id"]] = rr["cwe_description"]

            # Aggregate: CWE → language → (total_bytes, repo_set)
            cwe_lang_bytes: dict[str, dict[str, int]] = {}
            cwe_lang_repos: dict[str, dict[str, set[str]]] = {}
            for dr in data_rows:
                try:
                    cve_list = json.loads(dr["source_cves"] or "[]")
                    if not isinstance(cve_list, list):
                        continue
                except (TypeError, ValueError):
                    continue
                for cve_id in cve_list:
                    cwe = cve_to_cwe.get(cve_id)
                    if not cwe:
                        continue
                    lang = dr["language"]
                    cwe_lang_bytes.setdefault(cwe, {}).setdefault(lang, 0)
                    cwe_lang_bytes[cwe][lang] += int(dr["bytes"] or 0)
                    cwe_lang_repos.setdefault(cwe, {}).setdefault(lang, set()).add(
                        (cve_id,)  # count per CVE reference
                    )

            # Build result rows
            results: list[dict] = []
            for cwe in sorted(cwe_lang_bytes.keys()):
                lang_list = []
                for lang, total_bytes in sorted(
                    cwe_lang_bytes[cwe].items(), key=lambda x: x[1], reverse=True
                )[:10]:
                    lang_list.append({
                        "language": lang,
                        "total_bytes": total_bytes,
                        "repo_count": len(cwe_lang_repos.get(cwe, {}).get(lang, set())),
                    })
                results.append({
                    "cwe_id": cwe,
                    "cwe_description": cwe_to_desc.get(cwe, ""),
                    "languages": lang_list,
                })

            # Sort by total bytes descending, limit
            results.sort(
                key=lambda r: sum(l["total_bytes"] for l in r["languages"]),
                reverse=True,
            )
            return results[:limit]


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
