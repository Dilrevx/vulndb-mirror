from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class VersionRange(BaseModel):
    type: str  # SEMVER, ECOSYSTEM, GIT
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""

class AffectedPackage(BaseModel):
    ecosystem: str
    package_name: str
    version_ranges: list[VersionRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)

class GhsaRecord(BaseModel):
    ghsa_id: str
    cve_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    details: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    severity_type: str = ""
    affected: list[AffectedPackage] = Field(default_factory=list)
    references: list[dict] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    github_reviewed: bool = False
    withdrawn: Optional[datetime] = None
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    crawled_at: datetime = Field(default_factory=datetime.utcnow)
