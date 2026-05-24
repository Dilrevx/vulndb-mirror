from __future__ import annotations

from pathlib import Path

from vulndb_mirror.config import CrawlerSettings
from .repository import (
    DualWriteCveRepository,
    FileCveRepository,
    CveRepository,
    SqliteCveRepository,
)


def build_cve_repository(
    settings: CrawlerSettings, *, data_dir: str | None = None
) -> CveRepository:
    """Build a :class:`CveRepository` from *settings*.

    Args:
        settings:  Active :class:`~vulndb_mirror.config.CrawlerSettings`.
        data_dir:  Override the storage root directory.  When omitted,
                   ``settings.data_dir`` is used.
    """
    backend = settings.rawdb_storage_backend.lower()
    resolved_dir = data_dir if data_dir is not None else settings.data_dir
    sqlite_path = settings.rawdb_sqlite_path or str(Path(resolved_dir) / "raw.db")
    if data_dir is not None:
        sqlite_path = str(Path(resolved_dir) / "raw.db")

    file_repo = FileCveRepository(data_dir=resolved_dir)
    sqlite_repo = SqliteCveRepository(sqlite_path=sqlite_path)

    if backend == "file":
        return file_repo
    if backend == "sqlite":
        return sqlite_repo
    return DualWriteCveRepository(primary=sqlite_repo, secondary=file_repo)
