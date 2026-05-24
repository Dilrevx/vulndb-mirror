from vulndb_mirror.models.cve import (
    CveRecord,
    EnrichedCveEntry,
    TraceFrame,
    PatchMethod,
    CallTraceData,
)
from vulndb_mirror.models.ghsa import (
    VersionRange,
    AffectedPackage,
    GhsaRecord,
)

# Backward-compat aliases
RawAVDEntry = CveRecord
AVDCveEntry = EnrichedCveEntry

__all__ = [
    "CveRecord",
    "EnrichedCveEntry",
    "TraceFrame",
    "PatchMethod",
    "CallTraceData",
    "VersionRange",
    "AffectedPackage",
    "GhsaRecord",
    "RawAVDEntry",
    "AVDCveEntry",
]
