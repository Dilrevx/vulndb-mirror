from __future__ import annotations

import argparse
import json
import logging
import signal
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import uvicorn

from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.crawler.github.sbom import GitHubSbomCrawler
from vulndb_mirror.crawler.github.languages import GitHubLanguagesCrawler
from vulndb_mirror.server.api import create_app
from vulndb_mirror.storage.github_deps.ingest_service import (
    GithubSbomIngestService,
)
from vulndb_mirror.storage.github_deps.repository import (
    GitHubSbomRepository,
    DownstreamFixCommitsRepository,
)
from vulndb_mirror.storage.github_language.ingest_service import (
    GithubLanguagesIngestService,
)
from vulndb_mirror.storage.github_language.repository import GitHubLanguagesRepository
from vulndb_mirror.storage.cve.aliyun_ingest import AliyunIngestService
from vulndb_mirror.storage.cve.repository import CveRepository as RawRepository
from vulndb_mirror.storage.cve.models import now_iso
from vulndb_mirror.storage.cve.factory import build_cve_repository as build_raw_repository
from vulndb_mirror.storage.cve.trickest_ingest import TrickestIngestService
from vulndb_mirror.storage.cve.cvelistv5_ingest import CvelistV5IngestService
from vulndb_mirror.storage.cve.osv_ingest import OsvIngestService
from vulndb_mirror.crawler.ghsa.advisory_db import GhsaAdvisoryDbCrawler
from vulndb_mirror.storage.ghsa.repository import GhsaRepository
from vulndb_mirror.storage.ghsa.ingest import GhsaIngestService


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

    crawl_cve = sub.add_parser("crawl-cve", help="crawl CVE data (aliyun / cvelistv5 / trickest_cve / osv)")
    crawl_cve.add_argument(
        "--channel",
        default=None,
        choices=["aliyun", "trickest_cve", "cvelistv5", "osv"],
        help="data channel to crawl (default: value of CHANNEL env / 'aliyun')",
    )
    crawl_cve.add_argument(
        "--start-page",
        type=int,
        default=None,
        help="(aliyun channel) start from this list page",
    )
    crawl_cve.add_argument(
        "--full",
        action="store_true",
        default=False,
        help="(trickest_cve channel) re-process all files ignoring previous sync state",
    )

    crawl = sub.add_parser("crawl", help=argparse.SUPPRESS)
    crawl.add_argument(
        "--channel",
        default=None,
        choices=["aliyun", "trickest_cve", "cvelistv5", "osv"],
        help=argparse.SUPPRESS,
    )
    crawl.add_argument("--start-page", type=int, default=None, help=argparse.SUPPRESS)
    crawl.add_argument("--full", action="store_true", default=False, help=argparse.SUPPRESS)

    crawl_ghsa = sub.add_parser("crawl-ghsa", help="sync GitHub Advisory Database (GHSA)")
    crawl_ghsa.add_argument(
        "--full",
        action="store_true",
        default=False,
        help="re-process all files ignoring previous sync state",
    )

    retry = sub.add_parser("retry", help="retry explicit pages (aliyun channel)")
    retry.add_argument("--pages", nargs="+", type=int, required=True)

    sub.add_parser("gaps", help="show missing/failed page segments (aliyun channel)")
    sub.add_parser("api", help="start FastAPI service")

    sync = sub.add_parser(
        "sync",
        help="timed loop: crawl CVE data → GHSA → github-deps → github-languages (suitable for tmux)",
    )
    sync.add_argument(
        "--channel",
        nargs="+",
        default=["cvelistv5"],
        choices=["cvelistv5", "trickest_cve", "aliyun", "osv"],
        help="channels to crawl and scan for GitHub repos (default: cvelistv5)",
    )
    sync.add_argument(
        "--interval",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="seconds between full sync cycles (default: 3600)",
    )
    sync.add_argument(
        "--patch-only",
        action="store_true",
        default=False,
        help="GitHub cache: only process priority-0 repos (from patch_urls)",
    )
    sync.add_argument(
        "--github-max-repos",
        type=int,
        default=500,
        metavar="N",
        help="max repos per GitHub worker run per cycle (default: 500)",
    )
    sync.add_argument(
        "--github-max-seconds",
        type=int,
        default=1800,
        metavar="SECONDS",
        help="max seconds per GitHub worker run per cycle (default: 1800)",
    )

    deps = sub.add_parser(
        "github-deps",
        help="GitHub Dependency Graph (SBOM) cache",
    )
    deps_sub = deps.add_subparsers(dest="deps_command", required=True)

    deps_run = deps_sub.add_parser(
        "run",
        help="start long-running SBOM service (suitable for tmux)",
    )
    deps_run.add_argument(
        "--channel",
        nargs="+",
        default=["cvelistv5"],
        choices=["cvelistv5", "trickest_cve", "aliyun", "osv"],
        help="raw repository channels to scan for repos (default: cvelistv5)",
    )
    deps_run.add_argument(
        "--patch-only",
        action="store_true",
        default=False,
        help="only process priority-0 repos (those from patch_urls)",
    )
    deps_run.add_argument(
        "--discover-interval",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="seconds between periodic re-discovers of recent CVEs (default: 3600)",
    )

    deps_stats = deps_sub.add_parser("stats", help="show SBOM cache stats")
    deps_stats.add_argument(
        "--channel",
        default="cvelistv5",
        choices=["cvelistv5", "trickest_cve", "aliyun", "osv"],
    )

    langs = sub.add_parser(
        "github-languages",
        help="GitHub repository language composition cache",
    )
    langs_sub = langs.add_subparsers(dest="langs_command", required=True)

    langs_run = langs_sub.add_parser(
        "run",
        help="start long-running languages service (suitable for tmux)",
    )
    langs_run.add_argument(
        "--channel",
        nargs="+",
        default=["cvelistv5"],
        choices=["cvelistv5", "trickest_cve", "aliyun", "osv"],
        help="raw repository channels to scan for repos (default: cvelistv5)",
    )
    langs_run.add_argument(
        "--patch-only",
        action="store_true",
        default=False,
        help="only process priority-0 repos (those from patch_urls)",
    )
    langs_run.add_argument(
        "--discover-interval",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="seconds between periodic re-discovers of recent CVEs (default: 3600)",
    )

    langs_stats = langs_sub.add_parser("stats", help="show languages cache stats")
    langs_stats.add_argument(
        "--channel",
        default="cvelistv5",
        choices=["cvelistv5", "trickest_cve", "aliyun", "osv"],
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
    elif channel == "osv":
        base = settings.osv_data_dir
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


def _resolve_languages_sqlite_path(
    settings: CrawlerSettings, *, channel: str
) -> str:
    if settings.github_languages_sqlite_path:
        return settings.github_languages_sqlite_path
    if channel == "trickest_cve":
        base = settings.trickest_data_dir
    elif channel == "aliyun":
        base = settings.data_dir
    elif channel == "osv":
        base = settings.osv_data_dir
    else:
        base = settings.cvelistv5_data_dir
    return str(Path(base) / "raw.db")


def _build_languages_service(
    settings: CrawlerSettings,
    raw_repo: RawRepository,
    *,
    channel: str,
) -> GithubLanguagesIngestService:
    languages_repo = GitHubLanguagesRepository(
        sqlite_path=_resolve_languages_sqlite_path(settings, channel=channel)
    )
    crawler = GitHubLanguagesCrawler(github_token=settings.github_token)
    return GithubLanguagesIngestService(
        settings=settings,
        raw_repo=raw_repo,
        languages_repo=languages_repo,
        crawler=crawler,
    )


def _resolve_ghsa_sqlite_path(settings: CrawlerSettings) -> str:
    if settings.ghsa_sqlite_path:
        return settings.ghsa_sqlite_path
    return str(Path(settings.ghsa_data_dir) / "ghsa.db")


def _build_ghsa_service(settings: CrawlerSettings) -> GhsaIngestService:
    ghsa_repo = GhsaRepository(db_path=_resolve_ghsa_sqlite_path(settings))
    cfg = settings.to_crawl_config()
    cfg.data_dir = settings.ghsa_data_dir
    return GhsaIngestService(cfg, ghsa_repo)


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
        osv_repo = build_raw_repository(settings, data_dir=settings.osv_data_dir)

        trickest_config = settings.to_crawl_config()
        trickest_config.data_dir = settings.trickest_data_dir
        cv5_config = settings.to_crawl_config()
        cv5_config.data_dir = settings.cvelistv5_data_dir
        osv_config = settings.to_crawl_config()
        osv_config.data_dir = settings.osv_data_dir

        repositories = {
            "aliyun": aliyun_repo,
            "trickest_cve": trickest_repo,
            "cvelistv5": cvelistv5_repo,
            "osv": osv_repo,
        }
        services = {
            "aliyun": AliyunIngestService(settings.to_crawl_config(), aliyun_repo),
            "trickest_cve": TrickestIngestService(trickest_config, trickest_repo),
            "cvelistv5": CvelistV5IngestService(cv5_config, cvelistv5_repo),
            "osv": OsvIngestService(osv_config, osv_repo),
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

        languages_repo = GitHubLanguagesRepository(
            sqlite_path=_resolve_languages_sqlite_path(settings, channel="cvelistv5")
        )
        languages_service = GithubLanguagesIngestService(
            settings=settings,
            raw_repo=cvelistv5_repo,
            languages_repo=languages_repo,
            crawler=GitHubLanguagesCrawler(github_token=settings.github_token),
        )

        ghsa_service = _build_ghsa_service(settings)

        downstream_commits_repo = DownstreamFixCommitsRepository(
            sqlite_path=_resolve_sbom_sqlite_path(settings, channel="cvelistv5"),
            github_token=settings.github_token,
        )

        app = create_app(
            repositories,
            services,
            sbom_repo=sbom_repo,
            sbom_service=sbom_service,
            languages_repo=languages_repo,
            languages_service=languages_service,
            ghsa_repo=ghsa_service.repository,
            ghsa_service=ghsa_service,
            downstream_commits_repo=downstream_commits_repo,
        )
        uvicorn.run(
            app,
            host=settings.rawdb_api_host,
            port=settings.rawdb_api_port,
            log_level="info",
        )
        return

    # --- GitHub SBOM service -------------------------------------------------
    if args.command == "github-deps":
        if args.deps_command == "run":
            channels: list[str] = args.channel
            raw_repos: dict[str, RawRepository] = {}
            for ch in channels:
                if ch == "trickest_cve":
                    raw_repos[ch] = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
                elif ch == "cvelistv5":
                    raw_repos[ch] = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
                elif ch == "osv":
                    raw_repos[ch] = build_raw_repository(settings, data_dir=settings.osv_data_dir)
                else:
                    raw_repos[ch] = build_raw_repository(settings)
            # SBOM cache always lives in the cvelistv5 db (or GITHUB_SBOM_SQLITE_PATH)
            primary_channel = "cvelistv5" if "cvelistv5" in channels else channels[0]
            sbom_service = _build_sbom_service(
                settings, raw_repos[primary_channel], channel=primary_channel
            )
            priority = 0 if args.patch_only else None
            sbom_service.run_service(
                raw_repos=raw_repos,
                priority=priority,
                discover_interval_seconds=args.discover_interval,
            )
            return

        if args.deps_command == "stats":
            stats_channel = args.channel
            if stats_channel == "trickest_cve":
                stats_raw = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
            elif stats_channel == "cvelistv5":
                stats_raw = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
            elif stats_channel == "osv":
                stats_raw = build_raw_repository(settings, data_dir=settings.osv_data_dir)
            else:
                stats_raw = build_raw_repository(settings)
            sbom_service = _build_sbom_service(settings, stats_raw, channel=stats_channel)
            print(json.dumps(sbom_service.sbom_repo.stats(), ensure_ascii=False, indent=2))
            return

        return

    # --- GitHub Languages service --------------------------------------------
    if args.command == "github-languages":
        if args.langs_command == "run":
            channels: list[str] = args.channel
            raw_repos: dict[str, RawRepository] = {}
            for ch in channels:
                if ch == "trickest_cve":
                    raw_repos[ch] = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
                elif ch == "cvelistv5":
                    raw_repos[ch] = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
                elif ch == "osv":
                    raw_repos[ch] = build_raw_repository(settings, data_dir=settings.osv_data_dir)
                else:
                    raw_repos[ch] = build_raw_repository(settings)
            primary_channel = "cvelistv5" if "cvelistv5" in channels else channels[0]
            langs_service = _build_languages_service(
                settings, raw_repos[primary_channel], channel=primary_channel
            )
            priority = 0 if args.patch_only else None
            langs_service.run_service(
                raw_repos=raw_repos,
                priority=priority,
                discover_interval_seconds=args.discover_interval,
            )
            return

        if args.langs_command == "stats":
            stats_channel = args.channel
            if stats_channel == "trickest_cve":
                stats_raw = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
            elif stats_channel == "cvelistv5":
                stats_raw = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
            elif stats_channel == "osv":
                stats_raw = build_raw_repository(settings, data_dir=settings.osv_data_dir)
            else:
                stats_raw = build_raw_repository(settings)
            langs_service = _build_languages_service(settings, stats_raw, channel=stats_channel)
            print(json.dumps(langs_service.languages_repo.stats(), ensure_ascii=False, indent=2))
            return

        return

    # --- Sync loop -----------------------------------------------------------
    if args.command == "sync":
        channels: list[str] = args.channel
        interval: int = args.interval
        priority = 0 if args.patch_only else None
        github_max_repos: int = args.github_max_repos
        github_max_seconds: int = args.github_max_seconds

        raw_repos: dict[str, object] = {}
        for ch in channels:
            if ch == "trickest_cve":
                raw_repos[ch] = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
            elif ch == "cvelistv5":
                raw_repos[ch] = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
            elif ch == "osv":
                raw_repos[ch] = build_raw_repository(settings, data_dir=settings.osv_data_dir)
            else:
                raw_repos[ch] = build_raw_repository(settings)

        primary_channel = "cvelistv5" if "cvelistv5" in channels else channels[0]
        sbom_service = _build_sbom_service(settings, raw_repos[primary_channel], channel=primary_channel)
        langs_service = _build_languages_service(settings, raw_repos[primary_channel], channel=primary_channel)

        stop = threading.Event()

        def _on_signal(sig: int, _frame: object) -> None:
            logging.getLogger(__name__).info(
                "sync: signal %d received, stopping after current phase", sig
            )
            stop.set()

        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)

        logger = logging.getLogger(__name__)
        logger.info(
            "sync service started: channels=%s interval=%ds patch_only=%s "
            "github_max_repos=%d github_max_seconds=%d",
            channels, interval, args.patch_only, github_max_repos, github_max_seconds,
        )

        # Track last discover timestamp so subsequent cycles only scan
        # recently-updated CVE rows instead of re-scanning the whole table.
        last_discover_iso: Optional[str] = None

        while not stop.is_set():
            cycle_start = time.time()

            # Phase 1: crawl each channel
            for ch in channels:
                if stop.is_set():
                    break
                logger.info("sync: crawling channel=%s", ch)
                try:
                    if ch == "trickest_cve":
                        cfg = settings.to_crawl_config()
                        cfg.data_dir = settings.trickest_data_dir
                        TrickestIngestService(cfg, raw_repos[ch]).sync(full=False)
                    elif ch == "cvelistv5":
                        cfg = settings.to_crawl_config()
                        cfg.data_dir = settings.cvelistv5_data_dir
                        CvelistV5IngestService(cfg, raw_repos[ch]).sync(full=False)
                    elif ch == "osv":
                        cfg = settings.to_crawl_config()
                        cfg.data_dir = settings.osv_data_dir
                        OsvIngestService(cfg, raw_repos[ch]).sync(full=False)
                    else:
                        AliyunIngestService(settings.to_crawl_config(), raw_repos[ch]).crawl_incremental()
                except Exception as exc:
                    logger.error("sync: crawl channel=%s failed: %s", ch, exc)

            # Phase 2: GHSA sync
            if not stop.is_set():
                logger.info("sync: ghsa sync")
                try:
                    ghsa_service = _build_ghsa_service(settings)
                    ghsa_service.sync(full=False)
                except Exception as exc:
                    logger.error("sync: ghsa sync failed: %s", exc)

            # Phase 3: GitHub deps (discover + worker)
            if not stop.is_set():
                logger.info("sync: github-deps discover + worker")
                try:
                    for ch, repo in raw_repos.items():
                        sbom_service.raw_repo = repo
                        sbom_service.discover_from_recent(
                            channel=ch, since_iso=last_discover_iso
                        )
                    last_discover_iso = now_iso()
                    sbom_service.run_worker(
                        max_repos=github_max_repos,
                        max_seconds=github_max_seconds,
                        priority=priority,
                    )
                except Exception as exc:
                    logger.error("sync: github-deps phase failed: %s", exc)

            # Phase 4: GitHub languages (discover + worker)
            if not stop.is_set():
                logger.info("sync: github-languages discover + worker")
                try:
                    for ch, repo in raw_repos.items():
                        langs_service.raw_repo = repo
                        langs_service.discover_from_recent(
                            channel=ch, since_iso=last_discover_iso
                        )
                    langs_service.run_worker(
                        max_repos=github_max_repos,
                        max_seconds=github_max_seconds,
                        priority=priority,
                    )
                except Exception as exc:
                    logger.error("sync: github-languages phase failed: %s", exc)

            elapsed = time.time() - cycle_start
            wait = max(0.0, interval - elapsed)
            if not stop.is_set() and wait > 0:
                logger.info("sync: cycle done in %.0fs, sleeping %.0fs until next cycle", elapsed, wait)
                stop.wait(wait)

        logger.info("sync: stopped")
        return

    # --- Crawl GHSA ----------------------------------------------------------
    if args.command == "crawl-ghsa":
        ghsa_service = _build_ghsa_service(settings)
        result = ghsa_service.sync(full=args.full)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    # --- Crawl ---------------------------------------------------------------
    if args.command in ("crawl-cve", "crawl") and channel == "trickest_cve":
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

    if args.command in ("crawl-cve", "crawl") and channel == "cvelistv5":
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

    if args.command in ("crawl-cve", "crawl") and channel == "osv":
        repository = build_raw_repository(settings, data_dir=settings.osv_data_dir)
        osv_config = settings.to_crawl_config()
        osv_config.data_dir = settings.osv_data_dir
        service_osv = OsvIngestService(osv_config, repository)
        result = service_osv.sync(full=args.full if hasattr(args, "full") else False)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    # --- Aliyun channel (default) --------------------------------------------
    repository = build_raw_repository(settings)
    service = AliyunIngestService(settings.to_crawl_config(), repository)

    if args.command in ("crawl-cve", "crawl"):
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
