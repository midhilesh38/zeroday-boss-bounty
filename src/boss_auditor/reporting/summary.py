"""Shared aggregation logic for Phase 6 report generation."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from boss_auditor.core.models import Finding, RiskLevel, StarRating, SystemIdentity

TOP_N = 20


@dataclass(slots=True)
class ReportContext:
    baseline_identity: SystemIdentity
    target_identity: SystemIdentity
    all_findings: list[Finding]
    generated_at: _dt.datetime = field(default_factory=lambda: _dt.datetime.now(_dt.UTC))

    @property
    def top_findings(self) -> list[Finding]:
        return self.all_findings[:TOP_N]

    @property
    def total_count(self) -> int:
        return len(self.all_findings)

    @property
    def counts_by_risk(self) -> dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for f in self.all_findings:
            counts[f.risk_score.risk_level.value] += 1
        return counts

    @property
    def counts_by_star(self) -> dict[str, int]:
        counts = {star.value: 0 for star in StarRating}
        for f in self.all_findings:
            counts[f.risk_score.star_rating.value] += 1
        return counts

    @property
    def likely_false_positive_count(self) -> int:
        return sum(1 for f in self.all_findings if f.risk_score.likely_false_positive)

    @property
    def counts_by_section(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.all_findings:
            counts[f.section] = counts.get(f.section, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
