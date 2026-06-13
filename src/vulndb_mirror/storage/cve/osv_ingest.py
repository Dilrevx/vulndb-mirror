"""OSV.dev channel ingest service.

Periodically queries the OSV.dev API for vulnerabilities affecting configured
target packages and ecosystems, then maps results into
:class:`~vulndb_mirror.models.CveRecord` for storage.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from pydantic import BaseModel, Field

from vulndb_mirror.config import CrawlConfig
from vulndb_mirror.crawler.osv.client import OsvClient, DEFAULT_ECOSYSTEMS
from .models import now_iso
from .repository import CveRepository

logger = logging.getLogger(__name__)

_STATE_FILE = ".osv_state.json"


class OsvSyncResult(BaseModel):
    """Result of a single OSV sync run."""

    saved_entries: int = Field(default=0, ge=0)
    queried_packages: int = Field(default=0, ge=0)
    already_up_to_date: bool = False
    error: Optional[str] = None
    synced_at: str = Field(default_factory=now_iso)
    last_sync_iso: Optional[str] = None


class OsvIngestService:
    """Query the OSV.dev API and ingest vulnerability records.

    Args:
        config: Crawler runtime configuration.
        repository: CVE storage backend.
        packages: Optional list of ``(ecosystem, package_name)`` tuples to
                  monitor.  When omitted, falls back to the project's target
                  components (via ``target_components.py`` mapping).
        ecosystems: Ecosystems to query when *packages* is also omitted.
        on_sync_complete: Optional callback invoked after each sync cycle.
    """

    def __init__(
        self,
        config: CrawlConfig,
        repository: CveRepository,
        *,
        packages: Optional[list[tuple[str, str]]] = None,
        ecosystems: Optional[list[str]] = None,
        on_sync_complete: Optional[Callable[["OsvSyncResult"], None]] = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self._state_path = Path(config.data_dir) / _STATE_FILE
        self._on_sync_complete = on_sync_complete
        self._ecosystems = ecosystems or DEFAULT_ECOSYSTEMS

        # Build per-ecosystem package list
        self._packages: list[tuple[str, str]] = []
        if packages:
            self._packages = list(packages)
        else:
            self._packages = _default_target_packages(self._ecosystems)

        token = _resolve_osv_token(config)
        osv_base = _resolve_osv_base_url(config)
        self._client = OsvClient(
            token=token,
            base_url=osv_base,
            timeout=config.timeout,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sync(self, *, full: bool = False) -> OsvSyncResult:
        """Query OSV.dev for all configured packages and ingest results.

        Args:
            full: When True, re-query all packages regardless of last sync
                  state.  When False, only query packages not recently synced.
        """
        prev_sync_iso = self._load_last_sync()
        queried = 0
        saved = 0
        errors: list[str] = []

        for ecosystem, pkg_name in self._packages:
            try:
                vulns = self._client.query_all_for_package(pkg_name, ecosystem)
                queried += 1

                for raw in vulns:
                    entry = OsvClient.osv_to_cve_record(raw)
                    if entry is None:
                        continue
                    self.repository.upsert_raw(entry, page=0)
                    saved += 1

                if queried % 10 == 0:
                    logger.info(
                        "OSV sync: queried %d/%d packages, %d entries saved",
                        queried, len(self._packages), saved,
                    )
            except Exception as exc:
                msg = f"{ecosystem}/{pkg_name}: {exc}"
                logger.error("OSV sync error: %s", msg)
                errors.append(msg)

        synced_at = now_iso()
        self._save_state(synced_at)

        logger.info(
            "OSV sync complete: %d packages queried, %d entries saved",
            queried, saved,
        )

        result = OsvSyncResult(
            saved_entries=saved,
            queried_packages=queried,
            error="; ".join(errors) if errors else None,
            synced_at=synced_at,
            last_sync_iso=prev_sync_iso,
        )
        self._fire_hook(result)
        return result

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fire_hook(self, result: OsvSyncResult) -> None:
        if self._on_sync_complete is None:
            return
        try:
            self._on_sync_complete(result)
        except Exception as exc:
            logger.warning("OSV on_sync_complete hook failed: %s", exc)

    def _load_last_sync(self) -> Optional[str]:
        if self._state_path.exists():
            try:
                data = json.loads(self._state_path.read_text(encoding="utf-8"))
                return data.get("last_sync")
            except Exception:
                pass
        return None

    def _save_state(self, synced_at: str) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(
            json.dumps({"last_sync": synced_at}, indent=2),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_osv_token(config: CrawlConfig) -> Optional[str]:
    """Resolve OSV API token from config extras or env."""
    token = getattr(config, "osv_token", None)
    if token:
        return token
    import os
    return os.environ.get("OSV_TOKEN")


def _resolve_osv_base_url(config: CrawlConfig) -> str:
    base = getattr(config, "osv_base_url", None)
    if base:
        return base
    import os
    return os.environ.get("OSV_BASE_URL", "https://api.osv.dev")


def _default_target_packages(ecosystems: list[str]) -> list[tuple[str, str]]:
    """Build a default package list from the project target components.

    Maps the 40 target components to their OSV ecosystem + package name pairs.
    """
    pairs: list[tuple[str, str]] = []

    # Python packages (PyPI ecosystem)
    pypi_packages = [
        "tensorflow",
        "torch",
        "scikit-learn",
        "transformers",
        "mlflow",
        "langchain",
        "pandas",
        "numpy",
        "scipy",
        "fastapi",
        "urllib3",
        "opencv-python",
        "pillow",
        "pyyaml",
    ]
    # Python built-ins that have OSV entries
    pypi_stdlib = [
        "pickle5",
        "joblib",
    ]

    # Java packages (Maven ecosystem)
    maven_packages = [
        "org.springframework:spring-framework",
        "org.springframework.boot:spring-boot",
        "org.apache.struts:struts2-core",
        "com.fasterxml.jackson.core:jackson-databind",
        "com.alibaba:fastjson2",
        "com.thoughtworks.xstream:xstream",
        "org.dom4j:dom4j",
        "org.apache.xmlbeans:xmlbeans",
        "org.apache.tomcat:tomcat-catalina",
        "io.netty:netty-codec",
        "org.eclipse.jetty:jetty-server",
        "org.apache.kafka:kafka-clients",
        "org.apache.activemq:activemq-client",
        "org.apache.logging.log4j:log4j-core",
        "ch.qos.logback:logback-core",
        "org.mybatis:mybatis",
        "org.apache.solr:solr-core",
        "org.apache.shiro:shiro-core",
        "commons-fileupload:commons-fileupload",
        "commons-io:commons-io",
        "org.apache.commons:commons-text",
        "commons-beanutils:commons-beanutils",
        "commons-collections:commons-collections",
        "org.codehaus.groovy:groovy",
    ]

    if "PyPI" in ecosystems:
        for pkg in pypi_packages + pypi_stdlib:
            pairs.append(("PyPI", pkg))

    if "Maven" in ecosystems:
        for pkg in maven_packages:
            pairs.append(("Maven", pkg))

    return pairs
