"""OSV.dev REST API crawler.

Queries the OSV.dev API (https://api.osv.dev/v1) for vulnerability records
and maps them into :class:`~vulndb_mirror.models.CveRecord`.

API docs: https://osv.dev/docs/
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional
from urllib.parse import urljoin

import httpx

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.models import CveRecord

logger = logging.getLogger(__name__)

DEFAULT_OSV_BASE_URL = "https://api.osv.dev"
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_GH_PATCH_RE = re.compile(
    r"https://github\.com/[^/\s]+/[^/\s]+/(commit|pull|issues)/[^\s)>\"']*"
)

# Default target ecosystems matching project focus
DEFAULT_ECOSYSTEMS = ["PyPI", "Maven"]


class OsvClient:
    """HTTP client for the OSV.dev REST API.

    Args:
        token: Optional API token (reserved for future use by OSV.dev).
        base_url: OSV API base URL.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = DEFAULT_OSV_BASE_URL,
        timeout: int = 30,
    ) -> None:
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.Client] = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            headers: dict[str, str] = {"Accept": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(
        self,
        package_name: str,
        ecosystem: str,
        *,
        version: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Query OSV.dev for vulnerabilities affecting a package.

        POST /v1/query

        Args:
            package_name: Package name (e.g. ``jackson-databind``).
            ecosystem: Ecosystem identifier (``PyPI``, ``Maven``, etc.).
            version: Optional specific version to query.

        Returns:
            List of vulnerability dicts (OSV format).
        """
        body: dict[str, Any] = {
            "package": {"name": package_name, "ecosystem": ecosystem},
        }
        if version:
            body["version"] = version

        try:
            resp = self.client.post("/v1/query", json=body)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulns", [])
            logger.debug(
                "OSV query %s/%s%s → %d vulns",
                ecosystem, package_name,
                f"@{version}" if version else "",
                len(vulns),
            )
            return vulns
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "OSV query failed for %s/%s: HTTP %s",
                ecosystem, package_name, exc.response.status_code,
            )
            return []
        except Exception as exc:
            logger.error("OSV query error for %s/%s: %s", ecosystem, package_name, exc)
            return []

    def query_batch(
        self,
        queries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Batch query OSV.dev for vulnerabilities.

        POST /v1/querybatch

        Args:
            queries: List of query dicts, each with ``package`` and optional ``version``.

        Returns:
            Merged list of vulnerability dicts.
        """
        if not queries:
            return []
        try:
            resp = self.client.post("/v1/querybatch", json={"queries": queries})
            resp.raise_for_status()
            data = resp.json()
            results: list[dict[str, Any]] = []
            for entry in data.get("results", []):
                results.extend(entry.get("vulns", []))
            logger.debug("OSV batch query (%d queries) → %d vulns", len(queries), len(results))
            return results
        except httpx.HTTPStatusError as exc:
            logger.warning("OSV batch query failed: HTTP %s", exc.response.status_code)
            return []
        except Exception as exc:
            logger.error("OSV batch query error: %s", exc)
            return []

    def get_vuln(self, vuln_id: str) -> Optional[dict[str, Any]]:
        """Fetch a single vulnerability by its OSV ID.

        GET /v1/vulns/{id}
        """
        try:
            resp = self.client.get(f"/v1/vulns/{vuln_id}")
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                logger.debug("OSV vuln not found: %s", vuln_id)
            else:
                logger.warning("OSV get vuln %s failed: HTTP %s", vuln_id, exc.response.status_code)
            return None
        except Exception as exc:
            logger.error("OSV get vuln %s error: %s", vuln_id, exc)
            return None

    def query_all_for_package(
        self,
        package_name: str,
        ecosystem: str,
    ) -> list[dict[str, Any]]:
        """Query OSV for all vulnerabilities affecting any version of a package.

        Uses the query endpoint without a version filter, which returns vulns
        for all versions of the package.
        """
        return self.query(package_name, ecosystem)

    # ------------------------------------------------------------------
    # Conversion: OSV JSON → CveRecord
    # ------------------------------------------------------------------

    @staticmethod
    def osv_to_cve_record(raw: dict[str, Any]) -> Optional[CveRecord]:
        """Convert an OSV vulnerability dict into a :class:`CveRecord`.

        Returns ``None`` when the entry has no CVE alias and thus can't be
        keyed by CVE ID.
        """
        osv_id = raw.get("id", "")
        aliases = raw.get("aliases", [])
        cve_ids = [a for a in aliases if a.upper().startswith("CVE-")]

        # Use the first CVE alias as the primary key; fall back to OSV ID
        # if no CVE alias (e.g. PYSEC-only entries).
        cve_id = cve_ids[0] if cve_ids else osv_id
        if not cve_id:
            return None

        summary = raw.get("summary", "") or raw.get("details", "")[:200]
        description = raw.get("details", "") or raw.get("summary", "")
        severity, cvss_score, cvss_vector = _extract_osv_severity(raw)
        cwe_ids = _extract_osv_cwes(raw)
        cwe_id = cwe_ids[0] if cwe_ids else ""
        published = _parse_osv_date(raw.get("published"))
        modified = _parse_osv_date(raw.get("modified"))
        affected = _extract_osv_affected(raw)
        references, patch_urls = _extract_osv_references(raw)

        return CveRecord(
            cve_id=cve_id,
            title=summary,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cwe_id=cwe_id,
            cwe_description="",
            published_date=published,
            modified_date=modified,
            affected_software=affected,
            references=references,
            patch_urls=patch_urls,
            detail_url=_osv_detail_url(osv_id, aliases),
            crawled_at=datetime.now(timezone.utc),
        )


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------


def _extract_osv_severity(raw: dict[str, Any]) -> tuple[str, Optional[float], str]:
    """Extract severity/CVSS from OSV record.

    OSV stores severity in ``database_specific.severity`` or via CVSS vectors
    in ``severity`` blocks.  The ``score`` field may be a numeric string or a
    CVSS vector string (e.g. ``CVSS:3.1/AV:L/AC:L/...``).
    """
    for sev in raw.get("severity", []):
        sev_type = sev.get("type", "")
        if sev_type in ("CVSS_V3", "CVSS_V2"):
            score_raw = sev.get("score", "")
            score = _parse_cvss_score(score_raw)
            return _cvss_label(score), score, score_raw

    db_specific = raw.get("database_specific", {})
    db_severity = db_specific.get("severity", "")
    if db_severity:
        return db_severity.upper(), None, ""

    return "", None, ""


def _parse_cvss_score(score_raw: str) -> Optional[float]:
    """Extract the base score from a CVSS vector string or numeric string."""
    if not score_raw:
        return None
    # Try numeric first
    try:
        return float(score_raw)
    except ValueError:
        pass
    # Parse base score from CVSS vector: CVSS:3.1/AV:L/AC:L/.../E:H/...
    # The base score isn't directly in the vector string, so approximate from
    # the impact and exploitability metrics.  This is a rough approximation.
    m = re.match(r"CVSS:3\.\d/(.*)", score_raw)
    if not m:
        return None
    metrics = dict(p.split(":")[0:2] for p in m.group(1).split("/") if ":" in p)
    try:
        return _cvss_base_score(metrics)
    except Exception:
        return None


def _cvss_base_score(metrics: dict[str, str]) -> float:
    """Compute CVSS v3.x base score from metric abbreviations.

    Follows the CVSS v3.1 specification section 7.
    """
    # Impact sub-score (ISC)
    c = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("C", "N")[0] if metrics.get("C") else "N", 0.0)
    i = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("I", "N")[0] if metrics.get("I") else "N", 0.0)
    a = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("A", "N")[0] if metrics.get("A") else "N", 0.0)

    isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    scope_changed = metrics.get("S", "U") == "C"

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    if impact <= 0:
        return 0.0

    # Exploitability sub-score
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", "N")[0] if metrics.get("AV") else "N", 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", "L")[0] if metrics.get("AC") else "L", 0.77)
    pr = _cvss_privilege_required(metrics, scope_changed)
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", "N")[0] if metrics.get("UI") else "N", 0.85)

    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        f_impact = 1.08 * (impact + exploitability)
    else:
        f_impact = impact + exploitability

    if f_impact > 10.0:
        f_impact = 10.0
    return round(f_impact, 1) if f_impact < 10.0 else round(f_impact, 1)


def _cvss_privilege_required(metrics: dict[str, str], scope_changed: bool) -> float:
    pr = metrics.get("PR", "N")[0] if metrics.get("PR") else "N"
    if scope_changed:
        return {"N": 0.85, "L": 0.68, "H": 0.50}.get(pr, 0.85)
    else:
        return {"N": 0.85, "L": 0.62, "H": 0.27}.get(pr, 0.85)


def _cvss_label(score: Optional[float]) -> str:
    if score is None:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_osv_cwes(raw: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for db_specific in raw.get("database_specific", {}).get("cwe_ids", []):
        if isinstance(db_specific, str):
            cwes.append(db_specific)
    return cwes


def _extract_osv_affected(raw: dict[str, Any]) -> list[str]:
    items: list[str] = []
    for aff in raw.get("affected", []):
        pkg = aff.get("package", {})
        name = pkg.get("name", "")
        eco = pkg.get("ecosystem", "")
        label = f"{eco}/{name}" if eco and name else (name or eco)
        if label:
            items.append(label)
    return list(dict.fromkeys(items))


def _extract_osv_references(raw: dict[str, Any]) -> tuple[list[str], list[str]]:
    refs: list[str] = []
    patches: list[str] = []
    for ref in raw.get("references", []):
        url = ref.get("url", "")
        if not url:
            continue
        refs.append(url)
        ref_type = ref.get("type", "")
        if ref_type in ("FIX", "PATCH") or _GH_PATCH_RE.match(url):
            patches.append(url)
    return refs, patches


def _parse_osv_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _osv_detail_url(osv_id: str, aliases: list[str]) -> str:
    if aliases:
        cve = next((a for a in aliases if a.upper().startswith("CVE-")), None)
        if cve:
            return f"https://osv.dev/vulnerability/{cve}"
    return f"https://osv.dev/vulnerability/{osv_id}"
