"""Trickest CVE GitHub repository crawler.

Clones / pulls git@github.com:trickest/cve.git and parses each CVE markdown
file into :class:`~vulndb_mirror.models.RawAVDEntry`.

Each .md file follows the schema::

    ### [CVE-YYYY-NNNNN](https://cve.mitre.org/...)
    ![](https://img.shields.io/static/v1?label=Product&message=Foo&color=blue)
    ![](https://img.shields.io/static/v1?label=Version&message=1.0&color=brightgreen)

    ### Description
    <text>

    ### POC

    #### Reference
    - https://...

    #### Github
    - https://github.com/...
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.models import RawAVDEntry

logger = logging.getLogger(__name__)

_BADGE_RE = re.compile(r"!\[\]\(https://img\.shields\.io/static/v1\?([^)]+)\)")
_CVE_HEADING_RE = re.compile(r"###\s+\[CVE-\d{4}-\d+\]\((https?://[^)]+)\)")
_CVE_ID_RE = re.compile(r"CVE-(\d{4})-\d+", re.IGNORECASE)
# GitHub commit / PR / issue URLs are treated as patch candidates
_GH_PATCH_RE = re.compile(
    r"https://github\.com/[^/\s]+/[^/\s]+/(commit|pull|issues)/[^\s)>\"']*"
)

TRICKEST_REPO_URL_SSH = "git@github.com:trickest/cve.git"
TRICKEST_REPO_URL_HTTPS = "https://github.com/trickest/cve.git"


class TrickestCrawler:
    """Crawl the trickest/cve Git repository.

    Syncs the remote repo to a local path under ``config.data_dir``, then
    iterates over the year-bucketed CVE markdown files.
    """

    def __init__(self, config: CrawlConfig) -> None:
        self.config = config
        self._repo_path = Path(config.data_dir) / "trickest_repo"
        self._use_ssh: bool = bool(getattr(config, "git_clone_via_ssh", False))
        self._proxy: Optional[str] = getattr(config, "git_proxy", None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def repo_url(self) -> str:
        return TRICKEST_REPO_URL_SSH if self._use_ssh else TRICKEST_REPO_URL_HTTPS

    def sync_repo(self) -> str:
        """Clone or pull the trickest/cve repo. Returns the new HEAD commit hash."""
        env = self._git_env()
        if (self._repo_path / ".git").exists():
            logger.info("Pulling trickest/cve at %s", self._repo_path)
            subprocess.run(
                ["git", "-C", str(self._repo_path), "pull", "--ff-only"],
                check=True,
                env=env,
            )
        else:
            logger.info("Cloning %s → %s", self.repo_url, self._repo_path)
            self._repo_path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth=1", self.repo_url, str(self._repo_path)],
                check=True,
                env=env,
            )
        result = subprocess.run(
            ["git", "-C", str(self._repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def iter_entries(
        self,
        *,
        since_commit: Optional[str] = None,
        since_year: Optional[int] = None,
    ) -> Iterator[RawAVDEntry]:
        """Yield :class:`~vulndb_mirror.models.RawAVDEntry` for each CVE file.

        Args:
            since_commit: If given, only process files changed since this commit.
                          Falls back to full scan when the diff fails.
            since_year:   Skip CVE files from years strictly before this integer.
        """
        if since_commit:
            changed = self._files_changed_since(since_commit)
            paths: list[Path] = []
            for rel in changed:
                if rel.endswith(".md") and _CVE_ID_RE.search(rel):
                    p = self._repo_path / rel
                    if p.exists():
                        paths.append(p)
            logger.info(
                "Incremental mode: %d changed CVE files since %s", len(paths), since_commit
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
        paths: list[Path] = []
        for year_dir in sorted(self._repo_path.iterdir()):
            if not year_dir.is_dir():
                continue
            try:
                year = int(year_dir.name)
            except ValueError:
                continue
            if since_year is not None and year < since_year:
                continue
            paths.extend(sorted(year_dir.glob("CVE-*.md")))
        return paths

    def _files_changed_since(self, since_commit: str) -> list[str]:
        result = subprocess.run(
            ["git", "-C", str(self._repo_path), "diff", "--name-only", since_commit, "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(
                "git diff failed (commit=%s), falling back to full scan: %s",
                since_commit,
                result.stderr.strip(),
            )
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _parse_file(self, path: Path) -> Optional[RawAVDEntry]:
        m = _CVE_ID_RE.search(path.name)
        if not m:
            return None
        cve_id = f"CVE-{m.group(1)}-{path.stem.split('-', 2)[2]}".upper()

        text = path.read_text(encoding="utf-8", errors="replace")

        detail_url = _extract_detail_url(text, cve_id)
        description = _extract_section(text, "Description")
        products, _versions, vuln_type = _extract_badges(text)
        ref_links, github_links = _extract_poc_links(text)

        # patch_urls: commit/PR links from the curated Reference section only,
        # not from the PoC GitHub list (those are tools/scanners, not patches).
        patch_urls = [u for u in ref_links if _GH_PATCH_RE.match(u)]

        return RawAVDEntry(
            cve_id=cve_id,
            # Use the Vulnerability badge as a human-readable title; the CVE ID
            # alone carries no descriptive information.
            title=vuln_type or cve_id,
            description=description,
            # Products only; version strings are not paired with products in
            # trickest badges and are already mentioned in the description text.
            affected_software=products,
            # ref_links are the true CVE references (advisories, NVD, etc.).
            references=ref_links,
            patch_urls=patch_urls,
            # github_links are PoC/tool repos that mention this CVE — different
            # signal from references; stored in the dedicated poc_repos field.
            poc_repos=github_links,
            detail_url=detail_url,
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
# Pure parsing helpers
# ---------------------------------------------------------------------------


def _extract_detail_url(text: str, cve_id: str) -> str:
    m = _CVE_HEADING_RE.search(text)
    if m:
        return m.group(1)
    return f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"


def _extract_section(text: str, heading: str) -> str:
    pattern = re.compile(
        r"###\s+" + re.escape(heading) + r"\s*\n(.*?)(?=\n###|\Z)",
        re.DOTALL,
    )
    m = pattern.search(text)
    if not m:
        return ""
    return m.group(1).strip()


_KNOWN_BADGE_LABELS = {"Product", "Version", "Vulnerability"}


def _extract_badges(text: str) -> tuple[list[str], list[str], str]:
    """Parse all shields.io badge fields.

    Returns:
        products:    ``label=Product`` message values
        versions:    ``label=Version`` message values
        vuln_type:   ``label=Vulnerability`` message value (first occurrence)
    """
    products: list[str] = []
    versions: list[str] = []
    vuln_type: str = ""
    for badge_m in _BADGE_RE.finditer(text):
        try:
            qs = urllib.parse.parse_qs(badge_m.group(1))
        except Exception:
            continue
        label = qs.get("label", [""])[0]
        msg = urllib.parse.unquote_plus(qs.get("message", [""])[0]).strip()
        if not msg:
            continue
        if label == "Product":
            products.append(msg)
        elif label == "Version":
            versions.append(msg)
        elif label == "Vulnerability" and not vuln_type:
            vuln_type = msg
        elif label not in _KNOWN_BADGE_LABELS:
            logger.warning("Unknown shield badge label %r (message=%r)", label, msg)
    return products, versions, vuln_type


def _extract_poc_links(text: str) -> tuple[list[str], list[str]]:
    ref_links: list[str] = []
    github_links: list[str] = []

    ref_m = re.search(r"####\s+Reference\s*\n(.*?)(?=\n####|\n###|\Z)", text, re.DOTALL)
    if ref_m:
        ref_links = _find_urls(ref_m.group(1))

    gh_m = re.search(r"####\s+Github\s*\n(.*?)(?=\n####|\n###|\Z)", text, re.DOTALL)
    if gh_m:
        github_links = _find_urls(gh_m.group(1))

    return ref_links, github_links


def _find_urls(text: str) -> list[str]:
    return re.findall(r"https?://\S+", text)
