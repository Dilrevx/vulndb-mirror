"""Unit tests for github_sbom URL extraction and SPDX parsing."""

from __future__ import annotations

import unittest

from vulndb_mirror.crawler.github.sbom import GitHubSbomCrawler, ParsedPackage
from vulndb_mirror.crawler.github import RepoRef
from vulndb_mirror.crawler.github._refs import _parse_repo_url


class ParseRepoUrlTests(unittest.TestCase):
    def test_basic_https(self):
        self.assertEqual(_parse_repo_url("https://github.com/foo/bar"), ("foo", "bar"))

    def test_http_scheme(self):
        self.assertEqual(_parse_repo_url("http://github.com/foo/bar"), ("foo", "bar"))

    def test_lowercases_owner_repo(self):
        self.assertEqual(_parse_repo_url("https://github.com/Foo/BAR"), ("foo", "bar"))

    def test_strips_dot_git(self):
        self.assertEqual(
            _parse_repo_url("https://github.com/foo/bar.git"), ("foo", "bar")
        )

    def test_strips_trailing_slash(self):
        self.assertEqual(_parse_repo_url("https://github.com/foo/bar/"), ("foo", "bar"))

    def test_strips_subpath(self):
        self.assertEqual(
            _parse_repo_url("https://github.com/foo/bar/commit/abc123"),
            ("foo", "bar"),
        )

    def test_strips_query_string(self):
        self.assertEqual(
            _parse_repo_url("https://github.com/foo/bar?ref=main"), ("foo", "bar")
        )

    def test_strips_fragment(self):
        self.assertEqual(
            _parse_repo_url("https://github.com/foo/bar/blob/main/README.md#L1"),
            ("foo", "bar"),
        )

    def test_blocked_owner_sponsors(self):
        self.assertIsNone(_parse_repo_url("https://github.com/sponsors/anyone"))

    def test_blocked_owner_topics(self):
        self.assertIsNone(_parse_repo_url("https://github.com/topics/security"))

    def test_blocked_owner_advisories(self):
        self.assertIsNone(_parse_repo_url("https://github.com/advisories/GHSA-xxxx"))

    def test_non_github_url_returns_none(self):
        self.assertIsNone(_parse_repo_url("https://gitlab.com/foo/bar"))

    def test_owner_only_returns_none(self):
        self.assertIsNone(_parse_repo_url("https://github.com/foo"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(_parse_repo_url(""))


class ExtractRepoRefsTests(unittest.TestCase):
    def test_patch_repo_gets_priority_zero(self):
        refs = GitHubSbomCrawler.extract_repo_refs(
            refs=["https://github.com/foo/bar/issues/1"],
            patches=["https://github.com/foo/bar/commit/abc"],
        )
        self.assertEqual(refs, [RepoRef("foo", "bar", 0)])

    def test_ref_only_repo_gets_priority_one(self):
        refs = GitHubSbomCrawler.extract_repo_refs(
            refs=["https://github.com/foo/bar"], patches=[]
        )
        self.assertEqual(refs, [RepoRef("foo", "bar", 1)])

    def test_dedupes_across_lists(self):
        refs = GitHubSbomCrawler.extract_repo_refs(
            refs=[
                "https://github.com/foo/bar",
                "https://github.com/foo/bar/blob/main/x",
                "https://github.com/Foo/BAR.git",
            ],
            patches=[],
        )
        self.assertEqual(refs, [RepoRef("foo", "bar", 1)])

    def test_patch_only_when_not_in_refs(self):
        refs = GitHubSbomCrawler.extract_repo_refs(
            refs=[],
            patches=["https://github.com/foo/bar/commit/abc"],
        )
        self.assertEqual(refs, [RepoRef("foo", "bar", 0)])

    def test_drops_blocked_owners(self):
        refs = GitHubSbomCrawler.extract_repo_refs(
            refs=[
                "https://github.com/sponsors/anyone",
                "https://github.com/foo/bar",
            ],
            patches=[],
        )
        self.assertEqual(refs, [RepoRef("foo", "bar", 1)])

    def test_handles_none_inputs(self):
        self.assertEqual(GitHubSbomCrawler.extract_repo_refs(None, None), [])

    def test_returns_sorted_output(self):
        refs = GitHubSbomCrawler.extract_repo_refs(
            refs=[
                "https://github.com/zoo/zar",
                "https://github.com/aaa/bbb",
            ],
            patches=[],
        )
        self.assertEqual(
            refs,
            [RepoRef("aaa", "bbb", 1), RepoRef("zoo", "zar", 1)],
        )


def _build_sbom_fixture() -> dict:
    """Minimal SPDX 2.3 doc with npm/pypi/maven packages and a manifest root."""
    return {
        "sbom": {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-RootPackage-package.json",
                    "name": "com.example/app",
                    "versionInfo": "1.0.0",
                },
                {
                    "SPDXID": "SPDXRef-Package-lodash",
                    "name": "lodash",
                    "versionInfo": "4.17.21",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/lodash@4.17.21",
                        }
                    ],
                },
                {
                    "SPDXID": "SPDXRef-Package-debug",
                    "name": "debug",
                    "versionInfo": "4.3.4",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/debug@4.3.4",
                        }
                    ],
                },
                {
                    "SPDXID": "SPDXRef-Package-requests",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.31.0",
                        }
                    ],
                },
                {
                    "SPDXID": "SPDXRef-Package-spring",
                    "name": "org.springframework:spring-core",
                    "versionInfo": "5.3.30",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": (
                                "pkg:maven/org.springframework/spring-core@5.3.30"
                            ),
                        }
                    ],
                    "annotations": [
                        {"comment": "manifest_path: app/pom.xml"},
                    ],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-RootPackage-package.json",
                    "relatedSpdxElement": "SPDXRef-Package-lodash",
                    "relationshipType": "DEPENDS_ON",
                },
                {
                    "spdxElementId": "SPDXRef-Package-lodash",
                    "relatedSpdxElement": "SPDXRef-Package-debug",
                    "relationshipType": "DEPENDS_ON",
                },
                {
                    "spdxElementId": "SPDXRef-RootPackage-package.json",
                    "relatedSpdxElement": "SPDXRef-Package-requests",
                    "relationshipType": "DEPENDS_ON",
                },
            ],
        }
    }


class ParseSbomTests(unittest.TestCase):
    def setUp(self):
        self.parsed = GitHubSbomCrawler.parse_sbom(_build_sbom_fixture())
        self.by_name = {pkg.package_name: pkg for pkg in self.parsed}

    def test_drops_root_packages(self):
        self.assertNotIn("com.example/app", self.by_name)

    def test_extracts_npm_ecosystem(self):
        self.assertEqual(self.by_name["lodash"].ecosystem, "npm")

    def test_extracts_pypi_ecosystem(self):
        self.assertEqual(self.by_name["requests"].ecosystem, "pypi")

    def test_extracts_maven_ecosystem(self):
        self.assertEqual(
            self.by_name["org.springframework:spring-core"].ecosystem, "maven"
        )

    def test_direct_dependency(self):
        self.assertEqual(self.by_name["lodash"].relationship, "direct")
        self.assertEqual(self.by_name["requests"].relationship, "direct")

    def test_indirect_dependency(self):
        self.assertEqual(self.by_name["debug"].relationship, "indirect")

    def test_keeps_version_info(self):
        self.assertEqual(self.by_name["lodash"].version_info, "4.17.21")

    def test_keeps_purl(self):
        self.assertEqual(self.by_name["lodash"].purl, "pkg:npm/lodash@4.17.21")

    def test_extracts_manifest_path(self):
        self.assertEqual(
            self.by_name["org.springframework:spring-core"].manifest_path,
            "app/pom.xml",
        )

    def test_handles_empty_payload(self):
        self.assertEqual(GitHubSbomCrawler.parse_sbom({}), [])
        self.assertEqual(GitHubSbomCrawler.parse_sbom({"sbom": {}}), [])

    def test_handles_no_relationships(self):
        payload = {
            "sbom": {
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-x",
                        "name": "x",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/x@1.0.0",
                            }
                        ],
                    }
                ],
            }
        }
        parsed = GitHubSbomCrawler.parse_sbom(payload)
        self.assertEqual(len(parsed), 1)
        self.assertIsNone(parsed[0].relationship)


if __name__ == "__main__":
    unittest.main()
