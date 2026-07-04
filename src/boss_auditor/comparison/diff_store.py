"""Save and load `diff_results.json` -- the structured output required by
Phase 3, extended to carry the full Phase 4/5 enrichment (risk, confidence,
priority score, star rating) so `report` and `top20` can run against it
without recomputing the comparison."""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from boss_auditor.core.exceptions import ComparisonError
from boss_auditor.core.models import Finding, SystemIdentity
from boss_auditor.reporting.summary import ReportContext


def save_diff_results(
    findings: list[Finding],
    baseline_identity: SystemIdentity,
    target_identity: SystemIdentity,
    path: Path | str,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    ctx = ReportContext(
        baseline_identity=baseline_identity, target_identity=target_identity, all_findings=findings
    )
    payload = {
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(),
        "baseline_identity": baseline_identity.model_dump(mode="json"),
        "target_identity": target_identity.model_dump(mode="json"),
        "total_findings": ctx.total_count,
        "summary": {
            "counts_by_risk_level": ctx.counts_by_risk,
            "counts_by_star_rating": ctx.counts_by_star,
            "counts_by_section": ctx.counts_by_section,
            "likely_false_positive_count": ctx.likely_false_positive_count,
        },
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_diff_results(path: Path | str) -> tuple[SystemIdentity, SystemIdentity, list[Finding]]:
    path = Path(path)
    if not path.exists():
        raise ComparisonError(
            f"No diff results found at {path}. Run `compare` first."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        baseline_identity = SystemIdentity.model_validate(raw["baseline_identity"])
        target_identity = SystemIdentity.model_validate(raw["target_identity"])
        findings = [Finding.model_validate(f) for f in raw["findings"]]
    except Exception as exc:
        raise ComparisonError(f"Could not load diff results from {path}: {exc}") from exc
    return baseline_identity, target_identity, findings
