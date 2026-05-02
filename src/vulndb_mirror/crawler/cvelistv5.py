"""CVEProject/cvelistV5 GitHub repository crawler.

Shallow-clones https://github.com/CVEProject/cvelistV5 and parses each
CVE JSON 5.0 file into :class:`~vulndb_mirror.models.RawAVDEntry`.

Directory layout::

    cves/
      <year>/
        <thousands-bucket>/   # e.g. 0xxx, 1xxx, …
          CVE-<year>-<seq>.json
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.models import RawAVDEntry

logger = logging.getLogger(__name__)

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_GH_PATCH_RE = re.compile(
    r"https://github\.com/[^/\s]+/[^/\s]+/(commit|pull|issues)/[^\s)>\"']*"
)

CVELISTV5_REPO_URL_SSH = "git@github.com:CVEProject/cvelistV5.git"
CVELISTV5_REPO_URL_HTTPS = "https://github.com/CVEProject/cvelistV5.git"


class CvelistV5Crawler:
    """Crawl the CVEProject/cvelistV5 Git repository (shallow clone)."""

    def __init__(self, config: CrawlConfig) -> None:
        self.config = config
        self._repo_path = Path(config.data_dir) / "cvelistv5_repo"
        self._use_ssh: bool = bool(getattr(config, "git_clone_via_ssh", False))
        self._proxy: Optional[str] = getattr(config, "git_proxy", None)

    @property
    def repo_url(self) -> str:
        return CVELISTV5_REPO_URL_SSH if self._use_ssh else CVELISTV5_REPO_URL_HTTPS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sync_repo(self) -> str:
        """Clone (shallow) or pull the cvelistV5 repo. Returns new HEAD hash."""
        env = self._git_env()
        if (self._repo_path / ".git").exists():
            logger.info("Pulling cvelistV5 at %s", self._repo_path)
            subprocess.run(
                ["git", "-C", str(self._repo_path), "fetch", "--depth=1", "origin", "main"],
                check=True,
                env=env,
            )
            subprocess.run(
                ["git", "-C", str(self._repo_path), "reset", "--hard", "origin/main"],
                check=True,
                env=env,
            )
        else:
            logger.info("Cloning %s → %s (shallow)", self.repo_url, self._repo_path)
            self._repo_path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [
                    "git", "clone", "--depth=1", "--branch", "main",
                    "--single-branch", self.repo_url, str(self._repo_path),
                ],
                check=True,
                env=env,
            )
        result = subprocess.run(
            ["git", "-C", str(self._repo_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()

    def iter_entries(
        self,
        *,
        since_commit: Optional[str] = None,
        since_year: Optional[int] = None,
    ) -> Iterator[RawAVDEntry]:
        """Yield :class:`RawAVDEntry` for each CVE JSON file.

        Args:
            since_commit: Only process files changed since this commit.
                          Falls back to full scan when diff fails.
            since_year:   Skip CVE files from years before this integer.
        """
        if since_commit:
            changed = self._files_changed_since(since_commit)
            paths: list[Path] = []
            for rel in changed:
                if rel.endswith(".json") and _CVE_ID_RE.search(rel):
                    p = self._repo_path / rel
                    if p.exists():
                        paths.append(p)
            logger.info(
                "Incremental mode: %d changed CVE files since %s",
                len(paths), since_commit,
            )
        else:
            paths = self._all_cve_files(since_year=since_year)
            logger.info("Full scan: %d CVE files (since_year=%s)", len(paths), since_year)

        for path in paths:
            try:
                entry = self._parse_file(path)
                if entry is not None:
                    yield entry
            except Exception as exc:
                logger.warning("Skip %s – parse error: %s", path.name, exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _all_cve_files(self, since_year: Optional[int] = None) -> list[Path]:
        cves_root = self._repo_path / "cves"
        if not cves_root.exists():
            return []
        paths: list[Path] = []
        for year_dir in sorted(cves_root.iterdir()):
            if not year_dir.is_dir():
                continue
            try:
                year = int(year_dir.name)
            except ValueError:
                continue
            if since_year is not None and year < since_year:
                continue
            for bucket_dir in sorted(year_dir.iterdir()):
                if not bucket_dir.is_dir():
                    continue
                paths.extend(sorted(bucket_dir.glob("CVE-*.json")))
        return paths

    def _files_changed_since(self, since_commit: str) -> list[str]:
        result = subprocess.run(
            ["git", "-C", str(self._repo_path), "diff", "--name-only", since_commit, "HEAD"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            logger.warning(
                "git diff failed (commit=%s), falling back to full scan: %s",
                since_commit, result.stderr.strip(),
            )
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _parse_file(self, path: Path) -> Optional[RawAVDEntry]:
        data = json.loads(path.read_text(encoding="utf-8"))
        meta = data.get("cveMetadata", {})
        cve_id = meta.get("cveId", "")
        if not cve_id or meta.get("state") != "PUBLISHED":
            return None

        cna = data.get("containers", {}).get("cna", {})

        description = _extract_description(cna)
        title = cna.get("title", "") or cve_id
        affected = _extract_affected(cna)
        references, patch_urls = _extract_references(cna)
        severity, cvss_score, cvss_vector = _extract_metrics(cna, data)
        cwe_id, cwe_desc = _extract_cwe(cna)
        published = _parse_dt(meta.get("datePublished"))
        modified = _parse_dt(meta.get("dateUpdated"))

        return RawAVDEntry(
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_id=cwe_id,
            cwe_description=cwe_desc,
            published_date=published,
            modified_date=modified,
            affected_software=affected,
            references=references,
            patch_urls=patch_urls,
            detail_url=f"https://www.cve.org/CVERecord?id={cve_id}",
            crawled_at=datetime.utcnow(),
        )

    def _git_env(self) -> Optional[dict[str, str]]:
        if not self._proxy:
            return None
        env = os.environ.copy()
        for key in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
            env[key] = self._proxy
        return env


# ---------------------------------------------------------------------------
# Pure parsing helpers for CVE JSON 5.0
# ---------------------------------------------------------------------------


def _extract_description(cna: dict[str, Any]) -> str:
    for desc in cna.get("descriptions", []):
        if desc.get("lang", "").startswith("en"):
            return desc.get("value", "").strip()
    descs = cna.get("descriptions", [])
    return descs[0].get("value", "").strip() if descs else ""


def _extract_affected(cna: dict[str, Any]) -> list[str]:
    items: list[str] = []
    for aff in cna.get("affected", []):
        vendor = aff.get("vendor", "")
        product = aff.get("product", "")
        label = f"{vendor}/{product}" if vendor and product else (product or vendor)
        if label:
            items.append(label)
    return items


def _extract_references(cna: dict[str, Any]) -> tuple[list[str], list[str]]:
    refs: list[str] = []
    patches: list[str] = []
    for ref in cna.get("references", []):
        url = ref.get("url", "")
        if not url:
            continue
        refs.append(url)
        tags = ref.get("tags") or []
        if "patch" in tags or _GH_PATCH_RE.match(url):
            patches.append(url)
    return refs, patches


def _extract_metrics(
    cna: dict[str, Any], data: dict[str, Any]
) -> tuple[str, Optional[float], str]:
    for source in (cna, *data.get("containers", {}).get("adp", [])):
        for metric_block in source.get("metrics", []):
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                cvss = metric_block.get(key)
                if cvss:
                    return (
                        cvss.get("baseSeverity", ""),
                        cvss.get("baseScore"),
                        cvss.get("vectorString", ""),
                    )
    return "", None, ""


def _extract_cwe(cna: dict[str, Any]) -> tuple[str, str]:
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId", "")
            if cwe_id:
                return cwe_id, desc.get("description", "")
    return "", ""


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
