"""Integration tests for GithubSbomIngestService and GitHubSbomRepository."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.crawler.github_sbom import (
    GitHubSbomCrawler,
    ParsedPackage,
    RepoRef,
    SbomResult,
)
from vulndb_mirror.models import RawAVDEntry
from vulndb_mirror.storage.github_deps.ingest_service import (
    GithubSbomIngestService,
)
from vulndb_mirror.storage.github_deps.repository import GitHubSbomRepository
from vulndb_mirror.storage.raw.repositories import SqliteRawRepository


def _make_entry(cve_id: str, *, refs: list[str], patches: list[str]) -> RawAVDEntry:
    return RawAVDEntry(
        cve_id=cve_id,
        title=f"title for {cve_id}",
        description="",
        references=refs,
        patch_urls=patches,
    )


class _FakeCrawler(GitHubSbomCrawler):
    """Crawler whose ``fetch_sbom`` is driven by an in-memory script."""

    def __init__(self, scripted: dict[tuple[str, str], list[SbomResult]]):
        self._scripted = scripted
        self._calls: list[tuple[str, str, str | None]] = []

    def fetch_sbom(
        self, owner: str, repo: str, *, etag: str | None = None
    ) -> SbomResult:
        self._calls.append((owner, repo, etag))
        queue = self._scripted.get((owner, repo))
        if not queue:
            return SbomResult(
                status="error", http_status=None, payload=None, etag=None,
                error="no scripted result",
            )
        return queue.pop(0)


def _spdx_payload(packages: list[tuple[str, str, str]]) -> dict:
    """Build a minimal SPDX doc; *packages* = [(name, ecosystem, version), ...]"""
    pkg_blocks = [
        {
            "SPDXID": "SPDXRef-RootPackage-x",
            "name": "root",
        }
    ]
    for name, ecosystem, version in packages:
        pkg_blocks.append(
            {
                "SPDXID": f"SPDXRef-Package-{name}",
                "name": name,
                "versionInfo": version,
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:{ecosystem}/{name}@{version}",
                    }
                ],
            }
        )
    relationships = [
        {
            "spdxElementId": "SPDXRef-RootPackage-x",
            "relatedSpdxElement": f"SPDXRef-Package-{name}",
            "relationshipType": "DEPENDS_ON",
        }
        for name, _, _ in packages
    ]
    return {"sbom": {"packages": pkg_blocks, "relationships": relationships}}


class TempDbMixin:
    def _make_tempdir(self) -> Path:
        tmp = tempfile.mkdtemp(prefix="sbom-test-")
        self.addCleanup(self._cleanup, tmp)
        return Path(tmp)

    @staticmethod
    def _cleanup(path: str) -> None:
        import shutil

        shutil.rmtree(path, ignore_errors=True)


class EnqueueTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = self._make_tempdir()
        self.db_path = str(self.tmp / "raw.db")
        # Bootstrap schema via SqliteRawRepository
        self.raw = SqliteRawRepository(self.db_path)
        self.sbom = GitHubSbomRepository(self.db_path)

    def test_enqueue_inserts_pending_row(self):
        n = self.sbom.enqueue_many(
            [RepoRef("foo", "bar", 1)], source_cve="CVE-2024-1"
        )
        self.assertEqual(n, 1)
        row = self.sbom.query_by_repo("foo", "bar")
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["priority"], 1)
        self.assertEqual(row["source_cves"], ["CVE-2024-1"])

    def test_enqueue_promotes_priority_to_zero(self):
        self.sbom.enqueue_many([RepoRef("foo", "bar", 1)], source_cve="CVE-A")
        self.sbom.enqueue_many([RepoRef("foo", "bar", 0)], source_cve="CVE-B")
        row = self.sbom.query_by_repo("foo", "bar")
        self.assertEqual(row["priority"], 0)
        self.assertCountEqual(row["source_cves"], ["CVE-A", "CVE-B"])

    def test_enqueue_does_not_demote_priority(self):
        self.sbom.enqueue_many([RepoRef("foo", "bar", 0)], source_cve="CVE-A")
        self.sbom.enqueue_many([RepoRef("foo", "bar", 1)], source_cve="CVE-B")
        row = self.sbom.query_by_repo("foo", "bar")
        self.assertEqual(row["priority"], 0)

    def test_enqueue_resets_fetched_to_pending(self):
        # Simulate a repo that was already fetched
        self.sbom.enqueue_many([RepoRef("foo", "bar", 1)], source_cve="CVE-A")
        # Mark it as fetched (as the worker would)
        self.sbom.upsert_sbom(
            "foo", "bar",
            payload={"sbom": {}}, packages=[], etag=None, http_status=200,
        )
        self.assertEqual(self.sbom.query_by_repo("foo", "bar")["status"], "fetched")
        # A new CVE references the same repo — should reset to pending
        self.sbom.enqueue_many([RepoRef("foo", "bar", 1)], source_cve="CVE-B")
        row = self.sbom.query_by_repo("foo", "bar")
        self.assertEqual(row["status"], "pending")
        self.assertCountEqual(row["source_cves"], ["CVE-A", "CVE-B"])

    def test_enqueue_does_not_reset_skip_404(self):
        # skip_404 is terminal — a new CVE reference should not re-queue it
        self.sbom.enqueue_many([RepoRef("gone", "repo", 1)], source_cve="CVE-A")
        self.sbom.mark_status("gone", "repo", status="skip_404", http_status=404, error=None)
        self.sbom.enqueue_many([RepoRef("gone", "repo", 1)], source_cve="CVE-B")
        self.assertEqual(self.sbom.query_by_repo("gone", "repo")["status"], "skip_404")

    def test_next_batch_orders_by_priority(self):
        self.sbom.enqueue_many(
            [
                RepoRef("a", "low", 1),
                RepoRef("b", "high", 0),
                RepoRef("c", "low", 1),
            ],
            source_cve="CVE-X",
        )
        batch = self.sbom.next_batch(limit=10)
        self.assertEqual(batch[0].owner, "b")
        self.assertEqual(batch[0].priority, 0)


class DiscoverTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = self._make_tempdir()
        self.db_path = str(self.tmp / "raw.db")
        self.raw = SqliteRawRepository(self.db_path)
        self.sbom = GitHubSbomRepository(self.db_path)
        self.settings = CrawlerSettings()

    def test_discover_extracts_repos_from_recent_cves(self):
        self.raw.upsert_raw(
            _make_entry(
                "CVE-2024-100",
                refs=["https://github.com/foo/bar"],
                patches=["https://github.com/foo/bar/commit/abc"],
            ),
            page=1,
        )
        self.raw.upsert_raw(
            _make_entry(
                "CVE-2024-101",
                refs=["https://github.com/baz/qux/issues/2"],
                patches=[],
            ),
            page=1,
        )

        crawler = _FakeCrawler(scripted={})
        service = GithubSbomIngestService(
            settings=self.settings,
            raw_repo=self.raw,
            sbom_repo=self.sbom,
            crawler=crawler,
        )
        result = service.discover_from_recent(channel="cvelistv5")
        self.assertEqual(result.cves_scanned, 2)
        self.assertEqual(result.repos_seen, 2)
        self.assertEqual(result.repos_enqueued, 2)

        foo = self.sbom.query_by_repo("foo", "bar")
        baz = self.sbom.query_by_repo("baz", "qux")
        self.assertEqual(foo["priority"], 0)  # patch repo
        self.assertEqual(baz["priority"], 1)  # ref-only repo


class WorkerTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        self.tmp = self._make_tempdir()
        self.db_path = str(self.tmp / "raw.db")
        self.raw = SqliteRawRepository(self.db_path)
        self.sbom = GitHubSbomRepository(self.db_path)
        # Tiny budget knobs so the test doesn't actually block on bucket math
        self.settings = CrawlerSettings(
            github_sbom_concurrency=2,
            github_sbom_hourly_budget=1000,
        )

    def _seed(self, refs: list[RepoRef]) -> None:
        for r in refs:
            self.sbom.enqueue_many([r], source_cve=f"CVE-FOR-{r.owner}-{r.repo}")

    def test_worker_fetched_path_persists_packages(self):
        self._seed([RepoRef("foo", "bar", 0)])

        payload = _spdx_payload([("lodash", "npm", "4.17.21")])
        crawler = _FakeCrawler(
            scripted={
                ("foo", "bar"): [
                    SbomResult(
                        status="fetched",
                        http_status=200,
                        payload=payload,
                        etag='W/"abc"',
                    )
                ]
            }
        )
        service = GithubSbomIngestService(
            settings=self.settings,
            raw_repo=self.raw,
            sbom_repo=self.sbom,
            crawler=crawler,
        )
        result = service.run_worker(max_repos=10, max_seconds=5, concurrency=1)
        self.assertEqual(result.processed, 1)
        self.assertEqual(result.fetched, 1)

        repo = self.sbom.query_by_repo("foo", "bar")
        self.assertEqual(repo["status"], "fetched")
        self.assertEqual(repo["package_count"], 1)
        self.assertEqual(len(repo["packages"]), 1)
        self.assertEqual(repo["packages"][0]["package_name"], "lodash")
        self.assertEqual(repo["packages"][0]["ecosystem"], "npm")

        # Reverse lookup wired up
        hits = self.sbom.query_by_package(ecosystem="npm", name="lodash")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["owner"], "foo")
        self.assertIn("CVE-FOR-foo-bar", hits[0]["source_cves"])

    def test_worker_handles_404_403_and_not_modified(self):
        self._seed(
            [
                RepoRef("a", "missing", 1),
                RepoRef("b", "private", 1),
                RepoRef("c", "stable", 1),
            ]
        )
        crawler = _FakeCrawler(
            scripted={
                ("a", "missing"): [
                    SbomResult(
                        status="skip_404", http_status=404, payload=None, etag=None
                    )
                ],
                ("b", "private"): [
                    SbomResult(
                        status="skip_403", http_status=403, payload=None, etag=None
                    )
                ],
                ("c", "stable"): [
                    SbomResult(
                        status="not_modified",
                        http_status=304,
                        payload=None,
                        etag='W/"old"',
                    )
                ],
            }
        )
        service = GithubSbomIngestService(
            settings=self.settings,
            raw_repo=self.raw,
            sbom_repo=self.sbom,
            crawler=crawler,
        )
        result = service.run_worker(max_repos=10, max_seconds=5, concurrency=1)
        self.assertEqual(result.processed, 3)
        self.assertEqual(result.skipped_404, 1)
        self.assertEqual(result.skipped_403, 1)
        self.assertEqual(result.not_modified, 1)

        self.assertEqual(self.sbom.query_by_repo("a", "missing")["status"], "skip_404")
        self.assertEqual(self.sbom.query_by_repo("b", "private")["status"], "skip_403")
        # 304 → status stays 'fetched'
        self.assertEqual(self.sbom.query_by_repo("c", "stable")["status"], "fetched")

    def test_worker_priority_filter(self):
        self._seed(
            [
                RepoRef("hi", "p0", 0),
                RepoRef("lo", "p1", 1),
            ]
        )
        payload = _spdx_payload([("x", "npm", "1.0.0")])
        crawler = _FakeCrawler(
            scripted={
                ("hi", "p0"): [
                    SbomResult(
                        status="fetched", http_status=200, payload=payload, etag=None
                    )
                ],
                ("lo", "p1"): [
                    SbomResult(
                        status="fetched", http_status=200, payload=payload, etag=None
                    )
                ],
            }
        )
        service = GithubSbomIngestService(
            settings=self.settings,
            raw_repo=self.raw,
            sbom_repo=self.sbom,
            crawler=crawler,
        )
        # Restrict to priority 0
        result = service.run_worker(
            max_repos=10, max_seconds=5, concurrency=1, priority=0
        )
        self.assertEqual(result.processed, 1)
        self.assertEqual(self.sbom.query_by_repo("hi", "p0")["status"], "fetched")
        self.assertEqual(self.sbom.query_by_repo("lo", "p1")["status"], "pending")

    def test_worker_max_repos_caps_processing(self):
        self._seed(
            [
                RepoRef(f"o{i}", "r", 0)
                for i in range(5)
            ]
        )
        payload = _spdx_payload([])
        crawler = _FakeCrawler(
            scripted={
                (f"o{i}", "r"): [
                    SbomResult(
                        status="fetched", http_status=200, payload=payload, etag=None
                    )
                ]
                for i in range(5)
            }
        )
        service = GithubSbomIngestService(
            settings=self.settings,
            raw_repo=self.raw,
            sbom_repo=self.sbom,
            crawler=crawler,
        )
        result = service.run_worker(max_repos=2, max_seconds=5, concurrency=1)
        self.assertEqual(result.processed, 2)
        self.assertEqual(result.stopped_reason, "max_repos")

    def test_stats_after_mixed_run(self):
        self._seed(
            [RepoRef("ok", "ok", 0), RepoRef("dead", "dead", 1)]
        )
        payload = _spdx_payload([("a", "npm", "1.0")])
        crawler = _FakeCrawler(
            scripted={
                ("ok", "ok"): [
                    SbomResult(
                        status="fetched", http_status=200, payload=payload, etag=None
                    )
                ],
                ("dead", "dead"): [
                    SbomResult(
                        status="skip_404", http_status=404, payload=None, etag=None
                    )
                ],
            }
        )
        service = GithubSbomIngestService(
            settings=self.settings,
            raw_repo=self.raw,
            sbom_repo=self.sbom,
            crawler=crawler,
        )
        service.run_worker(max_repos=10, max_seconds=5, concurrency=1)
        stats = self.sbom.stats()
        self.assertEqual(stats.get("fetched"), 1)
        self.assertEqual(stats.get("skip_404"), 1)
        self.assertEqual(stats["total_packages"], 1)


if __name__ == "__main__":
    unittest.main()
