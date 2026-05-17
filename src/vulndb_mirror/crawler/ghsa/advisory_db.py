from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.models.ghsa import AffectedPackage, GhsaRecord, VersionRange

logger = logging.getLogger(__name__)

ADVISORY_DB_REPO_URL_SSH = "git@github.com:github/advisory-database.git"
ADVISORY_DB_REPO_URL_HTTPS = "https://github.com/github/advisory-database.git"


class GhsaAdvisoryDbCrawler:
    def __init__(self, config: CrawlConfig) -> None:
        self.config = config
        self._repo_path = Path(config.data_dir) / "advisory_database_repo"
        self._use_ssh: bool = bool(getattr(config, "git_clone_via_ssh", False))
        self._proxy: Optional[str] = getattr(config, "git_proxy", None)

    @property
    def repo_url(self) -> str:
        return ADVISORY_DB_REPO_URL_SSH if self._use_ssh else ADVISORY_DB_REPO_URL_HTTPS

    def sync_repo(self) -> str:
        env = self._git_env()
        if (self._repo_path / ".git").exists():
            logger.info("Pulling advisory-database at %s", self._repo_path)
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

    def iter_entries(self, *, since_commit: Optional[str] = None) -> Iterator[GhsaRecord]:
        if since_commit:
            changed = self._files_changed_since(since_commit)
            paths: list[Path] = []
            for rel in changed:
                if rel.endswith(".json") and "GHSA-" in rel:
                    p = self._repo_path / rel
                    if p.exists():
                        paths.append(p)
            logger.info(
                "Incremental mode: %d changed GHSA files since %s",
                len(paths), since_commit,
            )
        else:
            paths = self._all_advisory_files()
            logger.info("Full scan: %d GHSA files", len(paths))

        for path in paths:
            try:
                entry = self._parse_file(path)
                if entry is not None:
                    yield entry
            except Exception as exc:
                logger.warning("Skip %s – parse error: %s", path.name, exc)

    def _all_advisory_files(self) -> list[Path]:
        advisories_root = self._repo_path / "advisories"
        if not advisories_root.exists():
            return []
        # Layout: advisories/{github-reviewed|unreviewed}/{year}/{month}/{GHSA-id}/GHSA-id.json
        return sorted(advisories_root.rglob("GHSA-*.json"))

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

    def _parse_file(self, path: Path) -> Optional[GhsaRecord]:
        data = json.loads(path.read_text(encoding="utf-8"))
        ghsa_id = data.get("id", "")
        if not ghsa_id or not ghsa_id.startswith("GHSA-"):
            return None

        aliases: list[str] = data.get("aliases", [])
        cve_ids = [a for a in aliases if a.startswith("CVE-")]

        severity_list = data.get("severity", [])
        cvss_vector = ""
        severity_type = ""
        if severity_list:
            first = severity_list[0]
            cvss_vector = first.get("score", "")
            severity_type = first.get("type", "")

        db_specific: dict = data.get("database_specific", {})
        cwe_ids: list[str] = db_specific.get("cwe_ids", [])
        github_reviewed: bool = bool(db_specific.get("github_reviewed", False))

        affected_packages = _parse_affected(data.get("affected", []))

        references: list[dict] = [
            {"type": r.get("type", ""), "url": r.get("url", "")}
            for r in data.get("references", [])
        ]

        withdrawn_raw = data.get("withdrawn")
        withdrawn = _parse_dt(withdrawn_raw) if withdrawn_raw else None

        return GhsaRecord(
            ghsa_id=ghsa_id,
            cve_ids=cve_ids,
            summary=data.get("summary", ""),
            details=data.get("details", ""),
            cvss_score=None,
            cvss_vector=cvss_vector,
            severity_type=severity_type,
            affected=affected_packages,
            references=references,
            cwe_ids=cwe_ids,
            github_reviewed=github_reviewed,
            withdrawn=withdrawn,
            published=_parse_dt(data.get("published")),
            modified=_parse_dt(data.get("modified")),
            crawled_at=datetime.utcnow(),
        )

    def _git_env(self) -> Optional[dict[str, str]]:
        if not self._proxy:
            return None
        env = os.environ.copy()
        for key in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
            env[key] = self._proxy
        return env


def _parse_affected(affected_list: list[dict]) -> list[AffectedPackage]:
    result: list[AffectedPackage] = []
    for item in affected_list:
        pkg = item.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        package_name = pkg.get("name", "")
        if not ecosystem or not package_name:
            continue

        version_ranges: list[VersionRange] = []
        for rng in item.get("ranges", []):
            rng_type = rng.get("type", "")
            events: list[dict] = rng.get("events", [])
            introduced = ""
            fixed = ""
            last_affected = ""
            for event in events:
                if "introduced" in event and not introduced:
                    introduced = event["introduced"]
                elif "fixed" in event and not fixed:
                    fixed = event["fixed"]
                elif "last_affected" in event and not last_affected:
                    last_affected = event["last_affected"]
            version_ranges.append(VersionRange(
                type=rng_type,
                introduced=introduced,
                fixed=fixed,
                last_affected=last_affected,
            ))

        versions: list[str] = item.get("versions", [])
        result.append(AffectedPackage(
            ecosystem=ecosystem,
            package_name=package_name,
            version_ranges=version_ranges,
            versions=versions,
        ))
    return result


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
