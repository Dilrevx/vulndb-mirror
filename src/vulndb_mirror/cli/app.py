from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

import uvicorn

from vulndb_mirror.config import CrawlerSettings
from vulndb_mirror.server.api import create_app
from vulndb_mirror.storage.ingest_service import RawIngestService
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
    return parser


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

        app = create_app(repositories, services)
        uvicorn.run(
            app,
            host=settings.rawdb_api_host,
            port=settings.rawdb_api_port,
            log_level="info",
        )
        return

    # --- Crawl ---------------------------------------------------------------
    if args.command == "crawl" and channel == "trickest_cve":
        repository = build_raw_repository(settings, data_dir=settings.trickest_data_dir)
        trickest_config = settings.to_crawl_config()
        trickest_config.data_dir = settings.trickest_data_dir
        service = TrickestIngestService(trickest_config, repository)
        result = service.sync(full=args.full)
        print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
        return

    if args.command == "crawl" and channel == "cvelistv5":
        repository = build_raw_repository(settings, data_dir=settings.cvelistv5_data_dir)
        cv5_config = settings.to_crawl_config()
        cv5_config.data_dir = settings.cvelistv5_data_dir
        service_cv5 = CvelistV5IngestService(cv5_config, repository)
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
