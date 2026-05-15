"""Shared GitHub repo-reference types and URL parsing helpers.

Used by both the SBOM and languages crawlers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional


_GH_REPO_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?(?:[/?#].*)?$",
    re.IGNORECASE,
)

_BLOCKED_OWNERS: frozenset[str] = frozenset(
    {
        "sponsors",
        "marketplace",
        "settings",
        "orgs",
        "topics",
        "search",
        "advisories",
        "features",
        "about",
        "pricing",
        "security",
        "site",
        "login",
        "join",
        "logout",
        "notifications",
        "explore",
        "trending",
        "collections",
        "events",
    }
)


@dataclass(frozen=True)
class RepoRef:
    """A GitHub owner/repo reference along with its discovery priority.

    ``priority`` 0 means the URL appeared in a CVE's ``patch_urls`` (high
    signal: the fix lives there); 1 means it was only in ``references``.
    """

    owner: str
    repo: str
    priority: int


def _normalize_repo_segment(value: str) -> str:
    cleaned = value.strip()
    if cleaned.lower().endswith(".git"):
        cleaned = cleaned[: -len(".git")]
    return cleaned.lower()


def _parse_repo_url(url: str) -> Optional[tuple[str, str]]:
    """Extract ``(owner, repo)`` from a GitHub URL, or None if not a repo URL."""
    if not url:
        return None
    match = _GH_REPO_RE.match(url.strip())
    if not match:
        return None
    owner_raw, repo_raw = match.group(1), match.group(2)
    owner = _normalize_repo_segment(owner_raw)
    repo = _normalize_repo_segment(repo_raw)
    if not owner or not repo:
        return None
    if owner in _BLOCKED_OWNERS:
        return None
    if repo in {".", ".."}:
        return None
    return owner, repo


def extract_repo_refs(
    refs: Iterable[str], patches: Iterable[str]
) -> list[RepoRef]:
    """Pull unique GitHub ``(owner, repo)`` pairs out of CVE URLs.

    Priority 0 wins over 1 when the same repo appears in both lists.
    """
    patch_keys: set[tuple[str, str]] = set()
    for url in patches or []:
        parsed = _parse_repo_url(url)
        if parsed is not None:
            patch_keys.add(parsed)

    seen: dict[tuple[str, str], int] = {}
    for url in refs or []:
        parsed = _parse_repo_url(url)
        if parsed is None:
            continue
        priority = 0 if parsed in patch_keys else 1
        existing = seen.get(parsed)
        if existing is None or priority < existing:
            seen[parsed] = priority

    for parsed in patch_keys:
        seen.setdefault(parsed, 0)

    return [
        RepoRef(owner=owner, repo=repo, priority=priority)
        for (owner, repo), priority in sorted(seen.items())
    ]


__all__ = ["RepoRef", "extract_repo_refs", "_parse_repo_url"]
