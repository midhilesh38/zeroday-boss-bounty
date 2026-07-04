"""Core domain models shared across the whole pipeline.

Phase 1 scope note: `PluginResult` and `SystemProfile` are fully used by the
baseline/target collection phase implemented now. `Finding`, `RiskScore`,
and `StarRating` are defined here because later phases (differential engine,
risk engine, reporting) all depend on this exact shape -- but the engines
that *produce* `Finding` objects are out of scope until Phase 3/4.
"""

from __future__ import annotations

import datetime as _dt
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


class CollectionStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED_UNSAFE = "skipped_unsafe"
    NOT_APPLICABLE = "not_applicable"


class PluginResult(BaseModel):
    """The output of a single collector plugin run."""

    plugin_name: str
    section: str
    status: CollectionStatus
    data: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    collected_at: _dt.datetime = Field(default_factory=_utcnow)


class SystemIdentity(BaseModel):
    """Basic identity metadata about the machine a profile was collected
    from, so a profile is self-describing when compared later."""

    label: str  # e.g. "baseline-debian13" or "target-bossos"
    hostname: str | None = None
    kernel_release: str | None = None
    os_pretty_name: str | None = None
    architecture: str | None = None
    collected_at: _dt.datetime = Field(default_factory=_utcnow)
    collector_version: str = "0.1.0"


class SystemProfile(BaseModel):
    """A complete point-in-time snapshot of one system, made up of the
    combined results of every collector plugin that ran."""

    identity: SystemIdentity
    sections: dict[str, PluginResult] = Field(default_factory=dict)

    def add_result(self, result: PluginResult) -> None:
        self.sections[result.section] = result

    def summary(self) -> dict[str, str]:
        return {name: res.status.value for name, res in self.sections.items()}


class StarRating(StrEnum):
    CRITICAL = "★★★★★ Critical Candidate"
    HIGH = "★★★★ High Candidate"
    MEDIUM = "★★★ Medium Candidate"
    LOW = "★★ Low Candidate"
    INFO = "★ Informational"


class RiskLevel(StrEnum):
    """Categorical risk bucket for a difference. Deliberately NOT called
    a vulnerability rating -- see module note on `Finding` below."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ChangeType(StrEnum):
    NEW = "new"
    REMOVED = "removed"
    MODIFIED = "modified"


class RiskScore(BaseModel):
    """Confidence (0-100) that the classification is correct, plus a
    categorical risk bucket. Both are produced by a transparent, offline,
    rule-based classifier -- never a network call or paid API."""

    confidence: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    star_rating: StarRating
    likely_false_positive: bool = False


class Finding(BaseModel):
    """One detected difference between baseline and target, enriched with
    context for a human researcher.

    IMPORTANT: a `Finding` is always an *investigation candidate*, never a
    claim that something is a vulnerability. Nothing in this codebase
    should describe a `Finding` using that word.
    """

    finding_id: str
    section: str
    path: str
    change_type: ChangeType
    title: str
    description: str
    category: str
    baseline_value: Any = None
    target_value: Any = None
    risk_score: RiskScore
    why_it_matters: str
    possible_impact: str
    manual_verification_steps: list[str] = Field(default_factory=list)
    verification_commands: list[str] = Field(default_factory=list)
    suggested_fix: str | None = None
    mitre_attack_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    priority_score: float = 0.0
    # Phase-5 prioritization signals, kept on the record for transparency
    # about *why* a finding was ranked where it was.
    privilege_impact: bool = False
    attack_surface: bool = False
    persistence: bool = False
