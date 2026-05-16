"""DAO over the GitHub SBOM cache tables.

Schema is bootstrapped by :class:`SqliteRawRepository._init_db`; this class
is the canonical read/write surface for ``github_sbom_cache`` and
``github_sbom_packages``.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from vulndb_mirror.crawler.github.sbom import ParsedPackage
from vulndb_mirror.crawler.github import RepoRef
from vulndb_mirror.storage.raw.raw_models import now_iso

logger = logging.getLogger(__name__)


@dataclass
class SbomQueueItem:
    owner: str
    repo: str
    priority: int
    sbom_etag: Optional[str]




class GitHubSbomRepository:
    """SQLite-backed cache of GitHub Dependency Graph SBOMs."""

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
                    "SELECT priority, source_cves, status FROM github_sbom_cache "
                    "WHERE owner=? AND repo=?",
                    (ref.owner, ref.repo),
                ).fetchone()
                if row is None:
                    source = json.dumps([source_cve]) if source_cve else "[]"
                    conn.execute(
                        """
                        INSERT INTO github_sbom_cache(
                            owner, repo, status, priority, source_cves,
                            enqueued_at, updated_at
                        ) VALUES(?, ?, 'pending', ?, ?, ?, ?)
                        """,
                        (ref.owner, ref.repo, ref.priority, source, ts, ts),
                    )
                    touched += 1
                    continue

                # Merge: priority lowers (toward 0); source_cves dedupes.
                # Only reset to pending when a *new* CVE references an
                # already-cached repo — otherwise keep its current status
                # so the worker doesn't re-fetch the same repos every cycle.
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

                # Transient errors (500, network issues) should be
                # retryable when a new CVE references the repo.
                # 404/403 are permanent skips — repo doesn't exist or is
                # private/SBOM-disabled.
                if current_status in ("fetched", "not_modified", "error"):
                    new_status = "pending" if new_cve_added else current_status
                else:
                    new_status = current_status

                if new_status == "pending":
                    conn.execute(
                        """
                        UPDATE github_sbom_cache
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
                        UPDATE github_sbom_cache
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
    ) -> list[SbomQueueItem]:
        """Pick up to *limit* pending rows in (priority ASC, enqueued_at ASC) order."""
        clauses = ["status = 'pending'"]
        args: list[object] = []
        if priority is not None:
            clauses.append("priority = ?")
            args.append(int(priority))

        sql = (
            "SELECT owner, repo, priority, sbom_etag "
            "FROM github_sbom_cache "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY priority ASC, enqueued_at ASC "
            "LIMIT ?"
        )
        args.append(int(limit))
        with self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [
            SbomQueueItem(
                owner=row["owner"],
                repo=row["repo"],
                priority=int(row["priority"]),
                sbom_etag=row["sbom_etag"],
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def upsert_sbom(
        self,
        owner: str,
        repo: str,
        *,
        payload: dict,
        packages: list[ParsedPackage],
        etag: Optional[str],
        http_status: int,
    ) -> None:
        """Persist a freshly fetched SBOM and its parsed package rows."""
        ts = now_iso()
        payload_json = json.dumps(payload, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE github_sbom_cache
                SET status='fetched',
                    http_status=?,
                    error_message=NULL,
                    sbom_payload=?,
                    sbom_etag=?,
                    package_count=?,
                    fetched_at=?,
                    expires_at=NULL,
                    updated_at=?
                WHERE owner=? AND repo=?
                """,
                (http_status, payload_json, etag, len(packages), ts, ts, owner, repo),
            )
            conn.execute(
                "DELETE FROM github_sbom_packages WHERE owner=? AND repo=?",
                (owner, repo),
            )
            if packages:
                conn.executemany(
                    """
                    INSERT INTO github_sbom_packages(
                        owner, repo, manifest_path, ecosystem,
                        package_name, version_info, purl, relationship
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            owner,
                            repo,
                            pkg.manifest_path,
                            pkg.ecosystem,
                            pkg.package_name,
                            pkg.version_info,
                            pkg.purl,
                            pkg.relationship,
                        )
                        for pkg in packages
                    ],
                )
            conn.commit()

    def touch_not_modified(self, owner: str, repo: str) -> None:
        """304 path: keep payload/packages, just record the fetch time."""
        ts = now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE github_sbom_cache
                SET status='fetched',
                    http_status=304,
                    error_message=NULL,
                    fetched_at=?,
                    expires_at=NULL,
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
                UPDATE github_sbom_cache
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
                "SELECT * FROM github_sbom_cache WHERE owner=? AND repo=?",
                (owner, repo),
            ).fetchone()
            if row is None:
                return None
            packages = conn.execute(
                "SELECT manifest_path, ecosystem, package_name, version_info, "
                "purl, relationship FROM github_sbom_packages "
                "WHERE owner=? AND repo=? "
                "ORDER BY ecosystem, package_name",
                (owner, repo),
            ).fetchall()
        return _row_to_repo_dict(row, packages)

    def query_by_package(
        self, ecosystem: Optional[str], name: str, *, limit: int = 100
    ) -> list[dict]:
        clauses = ["package_name = ?"]
        args: list[object] = [name]
        if ecosystem:
            clauses.append("ecosystem = ?")
            args.append(ecosystem)
        sql = (
            "SELECT p.owner, p.repo, p.manifest_path, p.ecosystem, "
            "       p.package_name, p.version_info, p.purl, p.relationship, "
            "       c.priority, c.source_cves, c.fetched_at "
            "FROM github_sbom_packages AS p "
            "JOIN github_sbom_cache AS c "
            "  ON c.owner = p.owner AND c.repo = p.repo "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY c.priority ASC, p.owner, p.repo "
            "LIMIT ?"
        )
        args.append(int(limit))
        with self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
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
                    "manifest_path": row["manifest_path"],
                    "ecosystem": row["ecosystem"],
                    "package_name": row["package_name"],
                    "version_info": row["version_info"],
                    "purl": row["purl"],
                    "relationship": row["relationship"],
                    "priority": int(row["priority"]),
                    "source_cves": source_cves,
                    "fetched_at": row["fetched_at"],
                }
            )
        return results

    def stats(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(1) AS c FROM github_sbom_cache GROUP BY status"
            ).fetchall()
            pkg_total = conn.execute(
                "SELECT COUNT(1) AS c FROM github_sbom_packages"
            ).fetchone()["c"]
            pending_by_priority = conn.execute(
                "SELECT priority, COUNT(1) AS c FROM github_sbom_cache "
                "WHERE status='pending' GROUP BY priority"
            ).fetchall()
        out: dict = {row["status"]: int(row["c"]) for row in rows}
        out["total_packages"] = int(pkg_total)
        out["pending_by_priority"] = {
            int(row["priority"]): int(row["c"]) for row in pending_by_priority
        }
        return out


def _row_to_repo_dict(row: sqlite3.Row, packages: list[sqlite3.Row]) -> dict:
    try:
        source_cves = json.loads(row["source_cves"] or "[]")
    except (TypeError, ValueError):
        source_cves = []
    payload: Optional[dict]
    try:
        payload = json.loads(row["sbom_payload"]) if row["sbom_payload"] else None
    except (TypeError, ValueError):
        payload = None
    return {
        "owner": row["owner"],
        "repo": row["repo"],
        "status": row["status"],
        "priority": int(row["priority"]),
        "http_status": row["http_status"],
        "error_message": row["error_message"],
        "package_count": int(row["package_count"]),
        "source_cves": source_cves,
        "enqueued_at": row["enqueued_at"],
        "fetched_at": row["fetched_at"],
        "expires_at": row["expires_at"],
        "updated_at": row["updated_at"],
        "etag": row["sbom_etag"],
        "payload": payload,
        "packages": [
            {
                "manifest_path": pkg["manifest_path"],
                "ecosystem": pkg["ecosystem"],
                "package_name": pkg["package_name"],
                "version_info": pkg["version_info"],
                "purl": pkg["purl"],
                "relationship": pkg["relationship"],
            }
            for pkg in packages
        ],
    }


__all__ = ["GitHubSbomRepository", "SbomQueueItem"]
