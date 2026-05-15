"""GitHub Dependency Graph (SBOM) crawler.

Fetches SPDX SBOMs via ``GET /repos/{owner}/{repo}/dependency-graph/sbom``.
URL parsing and :class:`RepoRef` live in :mod:`._refs`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Optional

from vulndb_mirror.utils.commit_resolver import GitHubClient
from ._refs import RepoRef, extract_repo_refs, _parse_repo_url  # noqa: F401 — re-exported

logger = logging.getLogger(__name__)


@dataclass
class ParsedPackage:
    """A single package row parsed out of an SPDX SBOM document."""

    package_name: str
    manifest_path: Optional[str] = None
    ecosystem: Optional[str] = None
    version_info: Optional[str] = None
    purl: Optional[str] = None
    relationship: Optional[str] = None  # "direct" | "indirect"


@dataclass
class SbomResult:
    """Result of a single SBOM fetch attempt."""

    status: str  # fetched | not_modified | skip_404 | skip_403 | error
    http_status: Optional[int]
    payload: Optional[dict]
    etag: Optional[str]
    error: Optional[str] = None


class GitHubSbomCrawler:
    """Pure URL extraction + SBOM fetcher (sync; uses :class:`GitHubClient`)."""

    SBOM_PATH = "/repos/{owner}/{repo}/dependency-graph/sbom"

    def __init__(
        self, github_token: Optional[str], *, timeout: int = 30
    ) -> None:
        self._token = github_token
        self._client = GitHubClient(token=github_token, timeout=timeout)

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_repo_refs(
        refs: Iterable[str], patches: Iterable[str]
    ) -> list[RepoRef]:
        """Delegate to the module-level :func:`._refs.extract_repo_refs`."""
        return extract_repo_refs(refs, patches)

    @staticmethod
    def parse_sbom(payload: dict) -> list[ParsedPackage]:
        """Walk an SPDX 2.3 JSON document and return one row per package.

        - Ecosystem is parsed from the ``pkg:<ecosystem>/...`` purl scheme.
        - Direct vs indirect is inferred from the ``relationships`` block:
          packages reached via ``DEPENDS_ON`` from a manifest's root package
          are direct; others are indirect.
        """
        sbom = (payload or {}).get("sbom") or payload or {}
        packages = sbom.get("packages") or []
        if not isinstance(packages, list):
            return []

        relationships = sbom.get("relationships") or []
        direct_targets: set[str] = set()
        if isinstance(relationships, list):
            # SPDX root packages (one per manifest) start with SPDXRef-RootPackage
            root_ids = {
                pkg.get("SPDXID")
                for pkg in packages
                if isinstance(pkg, dict)
                and isinstance(pkg.get("SPDXID"), str)
                and pkg["SPDXID"].startswith("SPDXRef-RootPackage")
            }
            for rel in relationships:
                if not isinstance(rel, dict):
                    continue
                if rel.get("relationshipType") != "DEPENDS_ON":
                    continue
                if rel.get("spdxElementId") in root_ids:
                    target = rel.get("relatedSpdxElement")
                    if isinstance(target, str):
                        direct_targets.add(target)

        results: list[ParsedPackage] = []
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            spdx_id = pkg.get("SPDXID") if isinstance(pkg.get("SPDXID"), str) else None
            if spdx_id and spdx_id.startswith("SPDXRef-RootPackage"):
                # Manifest-level synthetic root; don't surface as a dependency.
                continue

            purl: Optional[str] = None
            for ref in pkg.get("externalRefs") or []:
                if not isinstance(ref, dict):
                    continue
                if ref.get("referenceType") == "purl":
                    locator = ref.get("referenceLocator")
                    if isinstance(locator, str):
                        purl = locator
                        break

            ecosystem: Optional[str] = None
            if purl and purl.startswith("pkg:"):
                # pkg:<ecosystem>/...
                rest = purl[len("pkg:") :]
                slash = rest.find("/")
                if slash > 0:
                    ecosystem = rest[:slash].lower() or None

            version = pkg.get("versionInfo")
            if not isinstance(version, str):
                version = None

            relationship: Optional[str]
            if spdx_id is not None and spdx_id in direct_targets:
                relationship = "direct"
            elif relationships:
                relationship = "indirect"
            else:
                relationship = None

            manifest_path: Optional[str] = None
            for note in pkg.get("annotations") or []:
                if isinstance(note, dict):
                    comment = note.get("comment")
                    if isinstance(comment, str) and comment.startswith("manifest_path:"):
                        manifest_path = comment.split(":", 1)[1].strip() or None
                        break

            results.append(
                ParsedPackage(
                    package_name=name.strip(),
                    manifest_path=manifest_path,
                    ecosystem=ecosystem,
                    version_info=version,
                    purl=purl,
                    relationship=relationship,
                )
            )
        return results

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def fetch_sbom(
        self, owner: str, repo: str, *, etag: Optional[str] = None
    ) -> SbomResult:
        """``GET /repos/{owner}/{repo}/dependency-graph/sbom``.

        Honors ``If-None-Match`` for conditional GET; rate-limit handling is
        delegated to :class:`GitHubClient`.
        """
        path = self.SBOM_PATH.format(owner=owner, repo=repo)
        headers: dict[str, str] = {}
        if etag:
            headers["If-None-Match"] = etag

        try:
            status, body, resp_headers = self._client.get_with_meta(
                path, headers=headers
            )
        except Exception as exc:
            logger.warning("SBOM fetch errored for %s/%s: %s", owner, repo, exc)
            return SbomResult(
                status="error",
                http_status=None,
                payload=None,
                etag=None,
                error=str(exc),
            )

        new_etag = resp_headers.get("etag") or resp_headers.get("ETag")

        if status == 200:
            if not isinstance(body, dict):
                return SbomResult(
                    status="error",
                    http_status=status,
                    payload=None,
                    etag=new_etag,
                    error="unexpected SBOM body shape",
                )
            return SbomResult(
                status="fetched",
                http_status=status,
                payload=body,
                etag=new_etag,
            )
        if status == 304:
            return SbomResult(
                status="not_modified",
                http_status=status,
                payload=None,
                etag=etag or new_etag,
            )
        if status == 404:
            return SbomResult(
                status="skip_404",
                http_status=status,
                payload=None,
                etag=None,
            )
        if status == 403:
            return SbomResult(
                status="skip_403",
                http_status=status,
                payload=None,
                etag=None,
                error="403 Forbidden (private/SBOM disabled)",
            )
        return SbomResult(
            status="error",
            http_status=status,
            payload=None,
            etag=None,
            error=f"unexpected status {status}",
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubSbomCrawler":
        return self

    def __exit__(self, *args) -> None:
        self.close()


__all__ = [
    "GitHubSbomCrawler",
    "RepoRef",
    "ParsedPackage",
    "SbomResult",
]
