"""GitHub repository languages crawler.

Fetches per-language byte counts via
``GET /repos/{owner}/{repo}/languages`` — the same data shown as the
language composition bar on a GitHub repo page.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from vulndb_mirror.utils.commit_resolver import GitHubClient

logger = logging.getLogger(__name__)


@dataclass
class LanguagesResult:
    """Result of a single languages fetch attempt."""

    status: str  # fetched | not_modified | skip_404 | skip_403 | error
    http_status: Optional[int]
    payload: Optional[dict]  # {"Python": 12345, "JavaScript": 6789, ...}
    etag: Optional[str]
    error: Optional[str] = None


class GitHubLanguagesCrawler:
    """Fetches language composition for GitHub repos (sync)."""

    LANGUAGES_PATH = "/repos/{owner}/{repo}/languages"

    def __init__(
        self, github_token: Optional[str], *, timeout: int = 30
    ) -> None:
        self._token = github_token
        self._client = GitHubClient(token=github_token, timeout=timeout)

    def fetch_languages(
        self, owner: str, repo: str, *, etag: Optional[str] = None
    ) -> LanguagesResult:
        """``GET /repos/{owner}/{repo}/languages``.

        Returns a dict of ``{language: bytes}`` on 200, or a terminal/error
        result on 304/404/403/other.
        """
        path = self.LANGUAGES_PATH.format(owner=owner, repo=repo)
        headers: dict[str, str] = {}
        if etag:
            headers["If-None-Match"] = etag

        try:
            status, body, resp_headers = self._client.get_with_meta(
                path, headers=headers
            )
        except Exception as exc:
            logger.warning("Languages fetch errored for %s/%s: %s", owner, repo, exc)
            return LanguagesResult(
                status="error",
                http_status=None,
                payload=None,
                etag=None,
                error=str(exc),
            )

        new_etag = resp_headers.get("etag") or resp_headers.get("ETag")

        if status == 200:
            if not isinstance(body, dict):
                return LanguagesResult(
                    status="error",
                    http_status=status,
                    payload=None,
                    etag=new_etag,
                    error="unexpected languages body shape",
                )
            return LanguagesResult(
                status="fetched",
                http_status=status,
                payload=body,
                etag=new_etag,
            )
        if status == 304:
            return LanguagesResult(
                status="not_modified",
                http_status=status,
                payload=None,
                etag=etag or new_etag,
            )
        if status == 404:
            return LanguagesResult(
                status="skip_404",
                http_status=status,
                payload=None,
                etag=None,
            )
        if status == 403:
            return LanguagesResult(
                status="skip_403",
                http_status=status,
                payload=None,
                etag=None,
                error="403 Forbidden (private repo or rate limit)",
            )
        return LanguagesResult(
            status="error",
            http_status=status,
            payload=None,
            etag=None,
            error=f"unexpected status {status}",
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubLanguagesCrawler":
        return self

    def __exit__(self, *args) -> None:
        self.close()


__all__ = ["GitHubLanguagesCrawler", "LanguagesResult"]
