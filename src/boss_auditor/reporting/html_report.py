"""Phase 6 — Simple HTML report renderer. No external CSS/JS, no CDN calls
-- the report must open and render correctly with zero network access."""

from __future__ import annotations

import html as _html

from boss_auditor.core.models import Finding, RiskLevel
from boss_auditor.reporting.summary import ReportContext

_RISK_COLORS = {
    RiskLevel.CRITICAL: "#b91c1c",
    RiskLevel.HIGH: "#c2410c",
    RiskLevel.MEDIUM: "#a16207",
    RiskLevel.LOW: "#15803d",
}

_STYLE = """
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; max-width: 980px; margin: 2rem auto; padding: 0 1rem; color: #1f2328; background: #fff; }
h1 { border-bottom: 3px solid #1f2328; padding-bottom: 0.5rem; }
h2 { margin-top: 2.5rem; border-bottom: 1px solid #d0d7de; padding-bottom: 0.3rem; }
.meta { color: #57606a; font-size: 0.95rem; }
.summary-grid { display: flex; gap: 2rem; flex-wrap: wrap; }
.summary-box { background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 6px; padding: 1rem 1.5rem; min-width: 220px; }
.summary-box h3 { margin-top: 0; font-size: 0.95rem; text-transform: uppercase; color: #57606a; }
.finding { border: 1px solid #d0d7de; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }
.finding-header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 0.5rem; }
.badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; color: white; font-size: 0.85rem; font-weight: 600; }
.stars { font-size: 1.1rem; }
.section-tag { font-family: monospace; background: #f6f8fa; padding: 0.1rem 0.4rem; border-radius: 4px; }
.evidence { background: #f6f8fa; padding: 0.75rem 1rem; border-radius: 6px; font-family: monospace; font-size: 0.9rem; white-space: pre-wrap; }
.disclaimer { font-style: italic; color: #57606a; margin-top: 0.75rem; }
ol, ul { margin: 0.3rem 0; }
code { background: #f6f8fa; padding: 0.1rem 0.3rem; border-radius: 4px; }
footer { margin-top: 3rem; color: #57606a; font-size: 0.85rem; border-top: 1px solid #d0d7de; padding-top: 1rem; }
"""


def _esc(value: object) -> str:
    return _html.escape(str(value))


def _finding_html(rank: int, f: Finding) -> str:
    color = _RISK_COLORS.get(f.risk_score.risk_level, "#57606a")
    verify_steps = (
        "<ol>" + "".join(f"<li>{_esc(s)}</li>" for s in f.manual_verification_steps) + "</ol>"
        if f.manual_verification_steps
        else "<p>(none recorded)</p>"
    )
    verify_cmds = (
        "<ul>" + "".join(f"<li><code>{_esc(c)}</code></li>" for c in f.verification_commands) + "</ul>"
        if f.verification_commands
        else "<p>(none recorded)</p>"
    )
    cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "n/a"

    return f"""
<div class="finding">
  <div class="finding-header">
    <h3>#{rank} &mdash; {_esc(f.title)}</h3>
    <span class="badge" style="background:{color};">{_esc(f.risk_score.risk_level.value)}</span>
  </div>
  <p class="stars">{_esc(f.risk_score.star_rating.value)} &middot; confidence {f.risk_score.confidence}/100 &middot; priority score {f.priority_score}</p>
  <p><span class="section-tag">{_esc(f.section)}</span> / <span class="section-tag">{_esc(f.path)}</span> &middot; change: {_esc(f.change_type.value)} &middot; category: {_esc(f.category)} &middot; CWE: {_esc(cwe)}</p>
  <p>{_esc(f.description)}</p>
  <p><strong>Why it matters:</strong> {_esc(f.why_it_matters)}</p>
  <p><strong>Possible impact:</strong> {_esc(f.possible_impact)}</p>
  <p><strong>Evidence (baseline &rarr; target):</strong></p>
  <div class="evidence">baseline: {_esc(f.baseline_value)}
target:   {_esc(f.target_value)}</div>
  <p><strong>Manual verification steps:</strong></p>
  {verify_steps}
  <p><strong>Verification commands:</strong></p>
  {verify_cmds}
  <p><strong>Suggested fix:</strong> {_esc(f.suggested_fix or "No specific remediation recorded -- review manually.")}</p>
  <p class="disclaimer">This is an investigation candidate for manual review, not a confirmed vulnerability.{' Flagged as likely false positive.' if f.risk_score.likely_false_positive else ''}</p>
</div>
"""


def render_html(ctx: ReportContext) -> str:
    risk_items = "".join(f"<li>{_esc(level)}: <strong>{count}</strong></li>" for level, count in ctx.counts_by_risk.items())
    star_items = "".join(f"<li>{_esc(star)}: <strong>{count}</strong></li>" for star, count in ctx.counts_by_star.items())
    section_items = "".join(f"<li>{_esc(section)}: <strong>{count}</strong></li>" for section, count in ctx.counts_by_section.items())

    findings_html = "".join(_finding_html(i, f) for i, f in enumerate(ctx.top_findings, 1))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>BOSS Differential Security Auditor -- Report</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>BOSS Differential Security Auditor</h1>
<p class="meta">
  Generated: {_esc(ctx.generated_at.isoformat())}<br>
  Baseline: <strong>{_esc(ctx.baseline_identity.label)}</strong> (collected {_esc(ctx.baseline_identity.collected_at.isoformat())})<br>
  Target: <strong>{_esc(ctx.target_identity.label)}</strong> (collected {_esc(ctx.target_identity.collected_at.isoformat())})
</p>
<p>All findings below are <strong>investigation candidates</strong> for manual review by a human researcher. None of them are automatic claims of a vulnerability.</p>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-box">
    <h3>Totals</h3>
    <p>Total differences: <strong>{ctx.total_count}</strong></p>
    <p>Likely false positives (flagged, not excluded): <strong>{ctx.likely_false_positive_count}</strong></p>
    <p>Showing top <strong>{len(ctx.top_findings)}</strong> by priority score.</p>
  </div>
  <div class="summary-box">
    <h3>By risk level</h3>
    <ul>{risk_items}</ul>
  </div>
  <div class="summary-box">
    <h3>By star rating</h3>
    <ul>{star_items}</ul>
  </div>
  <div class="summary-box">
    <h3>By section</h3>
    <ul>{section_items}</ul>
  </div>
</div>

<h2>Top {len(ctx.top_findings)} Findings</h2>
{findings_html}

<footer>Generated offline by the BOSS Differential Security Auditor. No network access, no paid APIs, no automatic exploitation was performed at any point.</footer>
</body>
</html>
"""
