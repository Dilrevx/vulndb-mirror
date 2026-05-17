from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from vulndb_mirror.models.ghsa import GhsaRecord

_DDL = """
CREATE TABLE IF NOT EXISTS ghsa_entries (
    ghsa_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    published TEXT,
    modified TEXT,
    github_reviewed INTEGER,
    withdrawn INTEGER,
    crawled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ghsa_cve_aliases (
    ghsa_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    PRIMARY KEY (ghsa_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_ghsa_cve ON ghsa_cve_aliases(cve_id);

CREATE TABLE IF NOT EXISTS ghsa_affected (
    ghsa_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    PRIMARY KEY (ghsa_id, ecosystem, package_name)
);

CREATE INDEX IF NOT EXISTS idx_ghsa_ecosystem ON ghsa_affected(ecosystem, package_name);
"""


def _dt_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


class GhsaRepository:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DDL)

    def upsert(self, entry: GhsaRecord) -> None:
        payload = entry.model_dump_json()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ghsa_entries (ghsa_id, payload, published, modified,
                    github_reviewed, withdrawn, crawled_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ghsa_id) DO UPDATE SET
                    payload=excluded.payload,
                    published=excluded.published,
                    modified=excluded.modified,
                    github_reviewed=excluded.github_reviewed,
                    withdrawn=excluded.withdrawn,
                    crawled_at=excluded.crawled_at
                """,
                (
                    entry.ghsa_id,
                    payload,
                    _dt_iso(entry.published),
                    _dt_iso(entry.modified),
                    1 if entry.github_reviewed else 0,
                    1 if entry.withdrawn else 0,
                    _dt_iso(entry.crawled_at) or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                ),
            )
            conn.execute(
                "DELETE FROM ghsa_cve_aliases WHERE ghsa_id = ?", (entry.ghsa_id,)
            )
            conn.executemany(
                "INSERT OR IGNORE INTO ghsa_cve_aliases (ghsa_id, cve_id) VALUES (?, ?)",
                [(entry.ghsa_id, cve_id) for cve_id in entry.cve_ids],
            )
            conn.execute(
                "DELETE FROM ghsa_affected WHERE ghsa_id = ?", (entry.ghsa_id,)
            )
            conn.executemany(
                """
                INSERT OR IGNORE INTO ghsa_affected (ghsa_id, ecosystem, package_name)
                VALUES (?, ?, ?)
                """,
                [(entry.ghsa_id, pkg.ecosystem, pkg.package_name) for pkg in entry.affected],
            )

    def get(self, ghsa_id: str) -> Optional[GhsaRecord]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM ghsa_entries WHERE ghsa_id = ?", (ghsa_id,)
            ).fetchone()
        if row is None:
            return None
        return GhsaRecord.model_validate_json(row["payload"])

    def get_by_cve_id(self, cve_id: str) -> list[GhsaRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT e.payload FROM ghsa_entries e
                JOIN ghsa_cve_aliases a ON a.ghsa_id = e.ghsa_id
                WHERE a.cve_id = ?
                """,
                (cve_id,),
            ).fetchall()
        return [GhsaRecord.model_validate_json(r["payload"]) for r in rows]

    def query(
        self,
        *,
        ecosystem: Optional[str] = None,
        package_name: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[int, list[GhsaRecord]]:
        conditions: list[str] = []
        params: list[object] = []

        if ecosystem or package_name:
            join = "JOIN ghsa_affected a ON a.ghsa_id = e.ghsa_id"
            if ecosystem:
                conditions.append("a.ecosystem = ?")
                params.append(ecosystem)
            if package_name:
                conditions.append("a.package_name = ?")
                params.append(package_name)
        else:
            join = ""

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        base = f"FROM ghsa_entries e {join} {where}"

        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(DISTINCT e.ghsa_id) {base}", params
            ).fetchone()[0]
            offset = (page - 1) * page_size
            rows = conn.execute(
                f"SELECT DISTINCT e.payload {base} ORDER BY e.ghsa_id LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()

        items = [GhsaRecord.model_validate_json(r["payload"]) for r in rows]
        return total, items

    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM ghsa_entries").fetchone()[0]
            reviewed = conn.execute(
                "SELECT COUNT(*) FROM ghsa_entries WHERE github_reviewed = 1"
            ).fetchone()[0]
            withdrawn = conn.execute(
                "SELECT COUNT(*) FROM ghsa_entries WHERE withdrawn = 1"
            ).fetchone()[0]
            eco_rows = conn.execute(
                """
                SELECT ecosystem, COUNT(DISTINCT ghsa_id) AS cnt
                FROM ghsa_affected
                GROUP BY ecosystem
                ORDER BY cnt DESC
                """
            ).fetchall()
        return {
            "total": total,
            "reviewed": reviewed,
            "withdrawn": withdrawn,
            "ecosystems": {r["ecosystem"]: r["cnt"] for r in eco_rows},
        }
