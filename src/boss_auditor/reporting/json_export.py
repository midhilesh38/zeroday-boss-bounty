"""Phase 6 — JSON export renderer. Includes every finding (not just the
top 20) since JSON is the machine-readable/complete-record format; the
Markdown/HTML reports are the human-facing top-20 summaries."""

from __future__ import annotations

import json

from boss_auditor.reporting.summary import ReportContext


def render_json(ctx: ReportContext) -> str:
    payload = {
        "generated_at": ctx.generated_at.isoformat(),
        "baseline": ctx.baseline_identity.model_dump(mode="json"),
        "target": ctx.target_identity.model_dump(mode="json"),
        "summary": {
            "total_findings": ctx.total_count,
            "likely_false_positive_count": ctx.likely_false_positive_count,
            "counts_by_risk_level": ctx.counts_by_risk,
            "counts_by_star_rating": ctx.counts_by_star,
            "counts_by_section": ctx.counts_by_section,
        },
        "top_20_finding_ids": [f.finding_id for f in ctx.top_findings],
        "findings": [f.model_dump(mode="json") for f in ctx.all_findings],
        "disclaimer": (
            "All entries in 'findings' are investigation candidates for manual "
            "review. None represent a confirmed vulnerability or an automatic "
            "exploitation attempt."
        ),
    }
    return json.dumps(payload, indent=2)
