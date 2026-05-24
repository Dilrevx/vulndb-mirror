# backward-compat shim — import from storage.cve instead
from vulndb_mirror.storage.cve.repository import (
    CveRepository as RawRepository,
    FileCveRepository as FileRawRepository,
    SqliteCveRepository as SqliteRawRepository,
    DualWriteCveRepository as DualWriteRawRepository,
)
from vulndb_mirror.storage.cve.models import (
    CveQueryResult as RawQueryResult,
    CveMeta as RawMeta,
    PageCheckpoint, PageGap, RetryRequest, RetryResult,
    CrawlPhaseResult, CrawlRunResult, now_iso,
)
from vulndb_mirror.storage.cve.factory import build_cve_repository as build_raw_repository
from vulndb_mirror.storage.cve.aliyun_ingest import AliyunIngestService as RawIngestService
from vulndb_mirror.storage.cve.cvelistv5_ingest import CvelistV5IngestService, CvelistV5SyncResult
from vulndb_mirror.storage.cve.trickest_ingest import TrickestIngestService
