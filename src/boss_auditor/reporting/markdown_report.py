"""Phase 6 — Markdown report renderer."""

from __future__ import annotations

from boss_auditor.core.models import Finding
from boss_auditor.reporting.summary import ReportContext


def _finding_block(rank: int, f: Finding) -> str:
    verify_cmds = (
        "\n".join(f"    - `{cmd}`" for cmd in f.verification_commands)
        if f.verification_commands
        else "    - (none recorded)"
    )
    verify_steps = (
        "\n".join(f"    {i}. {step}" for i, step in enumerate(f.manual_verification_steps, 1))
        if f.manual_verification_steps
        else "    (none recorded)"
    )
    cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "n/a"

    return f"""### {rank}. {f.risk_score.star_rating.value} -- {f.title}

- **Finding ID:** `{f.finding_id}`
- **Section / Path:** `{f.section}` / `{f.path}`
- **Change type:** {f.change_type.value}
- **Category:** {f.category}
- **Risk level:** {f.risk_score.risk_level.value} (confidence: {f.risk_score.confidence}/100, priority score: {f.priority_score})
- **Likely false positive:** {"yes" if f.risk_score.likely_false_positive else "no"}
- **CWE:** {cwe}

**Description:** {f.description}

**Why it matters:** {f.why_it_matters}

**Possible impact:** {f.possible_impact}

**Evidence (baseline -> target):**
```
baseline: {f.baseline_value!r}
target:   {f.target_value!r}
```

**Manual verification steps:**
{verify_steps}

**Verification commands:**
{verify_cmds}

**Suggested fix:** {f.suggested_fix or "No specific remediation recorded -- review manually."}

> This is an investigation candidate for manual review, not a confirmed vulnerability.
"""


def render_markdown(ctx: ReportContext) -> str:
    risk_lines = "\n".join(f"- **{level}:** {count}" for level, count in ctx.counts_by_risk.items())
    star_lines = "\n".join(f"- {star}: {count}" for star, count in ctx.counts_by_star.items())
    section_lines = "\n".join(f"- {section}: {count}" for section, count in ctx.counts_by_section.items())

    top_findings_md = "\n\n".join(
        _finding_block(i, f) for i, f in enumerate(ctx.top_findings, 1)
    )

    return f"""# BOSS Differential Security Auditor -- Report

Generated: {ctx.generated_at.isoformat()}

Baseline: **{ctx.baseline_identity.label}** (collected {ctx.baseline_identity.collected_at.isoformat()})
Target: **{ctx.target_identity.label}** (collected {ctx.target_identity.collected_at.isoformat()})

All findings below are **investigation candidates** for manual review by a human researcher.
None of them are automatic claims of a vulnerability.

## Executive Summary

- Total differences detected: **{ctx.total_count}**
- Likely false positives (flagged, not excluded): **{ctx.likely_false_positive_count}**
- Showing top **{len(ctx.top_findings)}** of {ctx.total_count} by priority score below.

## Security Summary

**By risk level:**
{risk_lines}

**By star rating:**
{star_lines}

**By section:**
{section_lines}

## Top {len(ctx.top_findings)} Findings

{top_findings_md}

---
*Generated offline by the BOSS Differential Security Auditor. No network access, no paid APIs, no automatic exploitation was performed at any point.*
"""
