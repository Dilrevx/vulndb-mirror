from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import uvicorn

from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.crawler.github_sbom import GitHubSbomCrawler
from vulndb_mirror.server.api import create_app
from vulndb_mirror.storage.github_sbom_ingest_service import (
    GithubSbomIngestService,
)
from vulndb_mirror.storage.github_sbom_repository import GitHubSbomRepository
from vulndb_mirror.storage.ingest_service import RawIngestService
from vulndb_mirror.storage.repositories import RawRepository
from vulndb_mirror.storage.repository_factory import build_raw_repository
from vulndb_mirror.storage.trickest_ingest_service import TrickestIngestService
from vulndb_mirror.storage.cvelistv5_ingest_service import CvelistV5IngestService


def _setup_logging(log_dir: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        handlers.append(
            logging.FileHandler(
                log_path / f"{timestamp}-crawler.log",
                encoding="utf-8",
                delay=True,
            )
        )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Vulnerability DB mirror tools")
    sub = parser.add_subparsers(dest="command", required=True)

    crawl = sub.add_parser("crawl", help="run incremental crawl / sync into raw storage")
    crawl.add_argument(
        "--channel",
        default=None,
        choices=["aliyun", "trickest_cve", "cvelistv5"],
        help="data channel to crawl (default: value of CHANNEL env / 'aliyun')",
    )
    crawl.add_argument(
        "--start-page",
        type=int,
        default=None,
        help="(aliyun channel) start from this list page",
    )
    crawl.add_argument(
        "--full",
        action="store_true",
        default=False,
        help="(trickest_cve channel) re-process all files ignoring previous sync state",
    )

    retry = sub.add_parser("retry", help="retry explicit pages (aliyun channel)")
    retry.add_argument("--pages", nargs="+", type=int, required=True)

    sub.add_parser("gaps", help="show missing/failed page segments (aliyun channel)")
    sub.add_parser("api", help="start FastAPI service")

    deps = sub.add_parser(
        "github-deps",
        help="GitHub Dependency Graph (SBOM) cache: discover, sync, stats",
    )
    deps_sub = deps.add_subparsers(dest="deps_command", required=True)

    deps_discover = deps_sub.add_parser(
        "discover",
        help="extract github repos from recent CVEs and enqueue them",
    )
    deps_discover.add_argument(
        "--channel",
        default="cvelistv5",
        choices=["cvelistv5", "trickest_cve", "aliyun"],
        help="raw repository to scan (default: cvelistv5)",
    )
    deps_discover.add_argument(
        "--since-days",
        type=int,
        default=None,
        help="only scan CVEs updated within the last N days (default: all)",
    )
    deps_discover.add_argument("--limit", type=int, default=None)

    deps_sync = deps_sub.add_parser(
        "sync", help="drain the SBOM queue (network)"
    )
    deps_sync.add_argument(
        "--channel",
        default="cvelistv5",
        choices=["cvelistv5", "trickest_cve", "aliyun"],
        help="raw repository channel (used to locate the SBOM sqlite)",
    )
    deps_sync.add_argument("--max-repos", type=int, default=200)
    deps_sync.add_argument("--max-seconds", type=int, default=300)
    deps_sync.add_argument(
        "--priority",
        default="all",
        choices=["0", "1", "all"],
        help="0 = patch repos only, 1 = ref-only, all = both (default: all)",
    )

    deps_stats = deps_sub.add_parser("stats", help="show SBOM cache stats")
    deps_stats.add_argument(
        "--channel",
        default="cvelistv5",
        choices=["cvelistv5", "trickest_cve", "aliyun"],
    )
    return parser


def _resolve_sbom_sqlite_path(
    settings: CrawlerSettings, *, channel: str
) -> str:
    """Decide where the SBOM cache lives.

    Honors ``settings.github_sbom_sqlite_path`` when set; otherwise falls
    back to ``<channel_data_dir>/raw.db`` so the cache co-locates with the
    raw CVE data.
    """
    if settings.github_sbom_sqlite_path:
        return settings.github_sbom_sqlite_path
    if channel == "trickest_cve":
        base = settings.trickest_data_dir
    elif channel == "aliyun":
        base = settings.data_dir
    else:
        base = settings.cvelistv5_data_dir
    return str(Path(base) / "raw.db")


def _build_sbom_service(
    settings: CrawlerSettings,
    raw_repo: RawRepository,
    *,
    channel: str,
) -> GithubSbomIngestService:
    sbom_repo = GitHubSbomRepository(
        sqlite_path=_resolve_sbom_sqlite_path(settings, channel=channel)
    )
    crawler = GitHubSbomCrawler(github_token=settings.github_token)
    return GithubSbomIngestService(
        settings=settings,
        raw_repo=raw_repo,
        sbom_repo=sbom_repo,
        crawler=crawler,
    )


def _make_sync_complete_hook(
    sbom_service: GithubSbomIngestService,
    settings: CrawlerSettings,
    *,
    channel: str,
):
    def _hook(result) -> None:
        since_iso = getattr(result, "last_sync_iso", None)
        sbom_service.discover_from_recent(channel=channel, since_iso=since_iso)
        if settings.github_sbom_auto_worker:
            sbom_service.run_worker(
                max_repos=settings.github_sbom_auto_worker_max_repos,
                max_seconds=settings.github_sbom_auto_worker_max_seconds,
                priority=0,
            )

    return _hook


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    settings = CrawlerSettings()
    _setup_logging(settings.log_dir)

    # Resolve active channel: CLI flag > env var CHANNEL > settings default
    channel = args.channel if hasattr(args, "channel") and args.channel else settings.channel

    # --- API server ----------------------------------------------------------
    if args.command == "api":
        aliyun_repo = build_raw_repository(settings)
        trickest_repo = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
        cvelistv5_repo = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)

        trickest_config = settings.to_crawl_config()
        trickest_config.data_dir = settings.trickest_data_dir
        cv5_config = settings.to_crawl_config()
        cv5_config.data_dir = settings.cvelistv5_data_dir

        repositories = {
            "aliyun": aliyun_repo,
            "trickest_cve": trickest_repo,
            "cvelistv5": cvelistv5_repo,
        }
        services = {
            "aliyun": RawIngestService(settings.to_crawl_config(), aliyun_repo),
            "trickest_cve": TrickestIngestService(trickest_config, trickest_repo),
            "cvelistv5": CvelistV5IngestService(cv5_config, cvelistv5_repo),
        }

        sbom_repo = GitHubSbomRepository(
            sqlite_path=_resolve_sbom_sqlite_path(settings, channel="cvelistv5")
        )
        sbom_service = GithubSbomIngestService(
            settings=settings,
            raw_repo=cvelistv5_repo,
            sbom_repo=sbom_repo,
            crawler=GitHubSbomCrawler(github_token=settings.github_token),
        )

        app = create_app(
            repositories,
            services,
            sbom_repo=sbom_repo,
            sbom_service=sbom_service,
        )
        uvicorn.run(
            app,
            host=settings.rawdb_api_host,
            port=settings.rawdb_api_port,
            log_level="info",
        )
        return

    # --- GitHub SBOM ops -----------------------------------------------------
    if args.command == "github-deps":
        deps_channel = args.channel
        if deps_channel == "trickest_cve":
            raw_repo = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
        elif deps_channel == "cvelistv5":
            raw_repo = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
        else:
            raw_repo = build_raw_repository(settings)

        sbom_service = _build_sbom_service(settings, raw_repo, channel=deps_channel)

        if args.deps_command == "discover":
            since_iso: Optional[str] = None
            if args.since_days is not None:
                since_iso = (
                    datetime.utcnow() - timedelta(days=int(args.since_days))
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
            result = sbom_service.discover_from_recent(
                channel=deps_channel,
                since_iso=since_iso,
                limit=args.limit,
            )
            print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
            return

        if args.deps_command == "sync":
            priority = None if args.priority == "all" else int(args.priority)
            result = sbom_service.run_worker(
                max_repos=args.max_repos,
                max_seconds=args.max_seconds,
                priority=priority,
            )
            print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
            return

        if args.deps_command == "stats":
            print(json.dumps(sbom_service.sbom_repo.stats(), ensure_ascii=False, indent=2))
            return

        return

    # --- Crawl ---------------------------------------------------------------
    if args.command == "crawl" and channel == "trickest_cve":
        repository = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
        trickest_config = settings.to_crawl_config()
        trickest_config.data_dir = settings.trickest_data_dir
        sbom_service = _build_sbom_service(
            settings, repository, channel="trickest_cve"
        )
        service = TrickestIngestService(
            trickest_config,
            repository,
            on_sync_complete=_make_sync_complete_hook(
                sbom_service, settings, channel="trickest_cve"
            ),
        )
        result = service.sync(full=args.full)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    if args.command == "crawl" and channel == "cvelistv5":
        repository = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
        cv5_config = settings.to_crawl_config()
        cv5_config.data_dir = settings.cvelistv5_data_dir
        sbom_service = _build_sbom_service(
            settings, repository, channel="cvelistv5"
        )
        service_cv5 = CvelistV5IngestService(
            cv5_config,
            repository,
            on_sync_complete=_make_sync_complete_hook(
                sbom_service, settings, channel="cvelistv5"
            ),
        )
        result = service_cv5.sync(full=args.full)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    # --- Aliyun channel (default) --------------------------------------------
    repository = build_raw_repository(settings)
    service = RawIngestService(settings.to_crawl_config(), repository)

    if args.command == "crawl":
        result = service.crawl_incremental(start_page=args.start_page)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    if args.command == "retry":
        result = service.retry_pages(args.pages)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    if args.command == "gaps":
        gap_items = repository.get_gaps(
            max_page=settings.max_pages,
            include_failed=True,
        )
        print(
            json.dumps(
                {
                    "meta": repository.get_meta().model_dump(),
                    "gaps": [g.model_dump() for g in gap_items],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
