"""Phase 6 — Reports.

`generate_all()` is the single entry point the CLI calls: given a list of
`Finding` objects and the two systems' identities, it writes all three
report formats (Markdown, HTML, JSON) to disk and returns their paths.
"""

from __future__ import annotations

from pathlib import Path

from boss_auditor.core.models import Finding, SystemIdentity
from boss_auditor.reporting.html_report import render_html
from boss_auditor.reporting.json_export import render_json
from boss_auditor.reporting.markdown_report import render_markdown
from boss_auditor.reporting.summary import ReportContext


def generate_all(
    findings: list[Finding],
    baseline_identity: SystemIdentity,
    target_identity: SystemIdentity,
    output_dir,
) -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx = ReportContext(
        baseline_identity=baseline_identity,
        target_identity=target_identity,
        all_findings=findings,
    )

    paths = {
        "markdown": output_dir / "report.md",
        "html": output_dir / "report.html",
        "json": output_dir / "report.json",
    }

    paths["markdown"].write_text(render_markdown(ctx), encoding="utf-8")
    paths["html"].write_text(render_html(ctx), encoding="utf-8")
    paths["json"].write_text(render_json(ctx), encoding="utf-8")

    return paths
