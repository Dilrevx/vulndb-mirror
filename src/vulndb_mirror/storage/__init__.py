from .cve.file_storage import CrawlStorage
from .cve.aliyun_ingest import AliyunIngestService
from .cve.models import PageCheckpoint, PageGap, CveQueryResult
from .cve.repository import (
    DualWriteCveRepository,
    FileCveRepository,
    CveRepository,
    SqliteCveRepository,
)
from .cve.factory import build_cve_repository

# backward-compat aliases
RawIngestService = AliyunIngestService
RawRepository = CveRepository
FileRawRepository = FileCveRepository
SqliteRawRepository = SqliteCveRepository
DualWriteRawRepository = DualWriteCveRepository
RawQueryResult = CveQueryResult
build_raw_repository = build_cve_repository

__all__ = [
    "CrawlStorage",
    "CveRepository",
    "FileCveRepository",
    "SqliteCveRepository",
    "DualWriteCveRepository",
    "AliyunIngestService",
    "PageCheckpoint",
    "PageGap",
    "CveQueryResult",
    "build_cve_repository",
    # backward-compat
    "RawRepository",
    "FileRawRepository",
    "SqliteRawRepository",
    "DualWriteRawRepository",
    "RawIngestService",
    "RawQueryResult",
    "build_raw_repository",
]
