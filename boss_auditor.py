#!/usr/bin/env python3
"""BOSS Differential Security Auditor -- command-line entry point.

Run from the project root (this file's directory):

    python3 boss_auditor.py scan-baseline    # scan the current (Debian 13) host
    python3 boss_auditor.py scan-target      # scan the BOSS OS host
    python3 boss_auditor.py compare          # diff + classify + rank + report
    python3 boss_auditor.py report           # (re)generate report files only
    python3 boss_auditor.py top20            # print the top 20 findings

`compare` is the one-command path: it loads the two saved profiles, runs
the differential engine (Phase 3), classifies every difference (Phase 4),
ranks them (Phase 5), writes `diff_results.json`, and by default also
writes the Markdown/HTML/JSON reports (Phase 6) to `output/`.

Fully offline. No network access, no paid APIs, no cloud services. Every
collector plugin is read-only -- see src/boss_auditor/core/safety.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

# --- src-layout bootstrap -------------------------------------------------
# The actual package lives in ./src/boss_auditor so that this file can be
# named exactly `boss_auditor.py` without colliding with the package of the
# same name. This must run before any `boss_auditor.*` import below.
_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))
# ---------------------------------------------------------------------------

import typer
from rich.console import Console
from rich.table import Table

from boss_auditor.comparison.diff_store import load_diff_results, save_diff_results
from boss_auditor.comparison.engine import compare_profiles
from boss_auditor.comparison.intelligence import build_findings
from boss_auditor.core.config import load_config
from boss_auditor.core.constants import BASELINE_PROFILE_NAME, TARGET_PROFILE_NAME
from boss_auditor.core.exceptions import BossAuditorError
from boss_auditor.core.logging import setup_logging
from boss_auditor.core.models import Finding, SystemIdentity
from boss_auditor.core.profile_store import load_profile, save_profile
from boss_auditor.plugins.registry import get_registry
from boss_auditor.reporting import generate_all

app = typer.Typer(
    name="boss-auditor",
    help="Read-only differential security auditor: Debian 13 baseline vs. BOSS OS target.",
    add_completion=False,
)
console = Console()

CONFIG_PATH = _PROJECT_ROOT / "config" / "settings.yaml"
PROFILE_DIR = _PROJECT_ROOT / "profiles"
OUTPUT_DIR = _PROJECT_ROOT / "output"
DIFF_RESULTS_PATH = OUTPUT_DIR / "diff_results.json"

BASELINE_PATH = PROFILE_DIR / BASELINE_PROFILE_NAME
TARGET_PATH = PROFILE_DIR / TARGET_PROFILE_NAME


def _run_scan(label: str, save_path: Path) -> None:
    setup_logging()
    config = load_config(CONFIG_PATH)
    registry = get_registry()
    identity = SystemIdentity(label=label)

    console.print(f"[bold]Scanning host[/bold] -- label={label!r}")
    profile = registry.run_all(identity=identity, config=config)
    saved_path = save_profile(profile, save_path)

    summary = profile.summary()
    ok = sum(1 for s in summary.values() if s == "ok")
    console.print(f"[green]Done.[/green] {ok}/{len(summary)} sections collected successfully.")
    for name, status in summary.items():
        color = "green" if status == "ok" else "yellow"
        console.print(f"  [{color}]{status:8s}[/{color}] {name}")
    console.print(f"Profile saved to: [bold]{saved_path}[/bold]")


@app.command("list-plugins")
def list_plugins() -> None:
    """Show every registered collector plugin (quick sanity check before
    scanning a new machine)."""
    setup_logging()
    config = load_config(CONFIG_PATH)
    registry = get_registry()

    table = Table(title="Registered Collector Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Section", style="magenta")
    table.add_column("Enabled")

    for plugin_cls in sorted(registry.all_plugins(), key=lambda p: p.name):
        enabled = "yes" if config.is_plugin_enabled(plugin_cls.name) else "no"
        table.add_row(plugin_cls.name, plugin_cls.section, enabled)

    console.print(table)


@app.command("scan-baseline")
def scan_baseline() -> None:
    """Scan the CURRENT host (run this on clean Debian 13) and save it as
    the baseline profile."""
    _run_scan("baseline-debian13", BASELINE_PATH)


@app.command("scan-target")
def scan_target() -> None:
    """Scan the CURRENT host (run this on BOSS OS) and save it as the
    target profile."""
    _run_scan("target-bossos", TARGET_PATH)


def _print_findings_table(findings: list[Finding], limit: int = 20) -> None:
    table = Table(title=f"Top {min(limit, len(findings))} Findings (of {len(findings)} total)")
    table.add_column("#", justify="right")
    table.add_column("Star Rating")
    table.add_column("Risk")
    table.add_column("Conf.", justify="right")
    table.add_column("Section")
    table.add_column("Title")

    risk_colors = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "green"}

    for i, f in enumerate(findings[:limit], 1):
        risk_style = risk_colors.get(f.risk_score.risk_level.value, "white")
        table.add_row(
            str(i),
            f.risk_score.star_rating.value,
            f"[{risk_style}]{f.risk_score.risk_level.value}[/{risk_style}]",
            f"{f.risk_score.confidence}",
            f.section,
            f.title + (" [dim](likely false positive)[/dim]" if f.risk_score.likely_false_positive else ""),
        )
    console.print(table)


@app.command("compare")
def compare(
    no_report: bool = typer.Option(
        False, "--no-report", help="Skip generating Markdown/HTML/JSON reports."
    ),
) -> None:
    """Run the full pipeline: load baseline + target profiles, diff them
    (Phase 3), classify every difference (Phase 4), rank them (Phase 5),
    save diff_results.json, print the top 20, and (by default) generate
    reports (Phase 6). This is the single command to run for the
    competition."""
    setup_logging()

    if not BASELINE_PATH.exists() or not TARGET_PATH.exists():
        console.print("[bold red]Missing profile(s).[/bold red]")
        if not BASELINE_PATH.exists():
            console.print(f"  Expected baseline at: {BASELINE_PATH} -- run `scan-baseline` first.")
        if not TARGET_PATH.exists():
            console.print(f"  Expected target at: {TARGET_PATH} -- run `scan-target` first.")
        raise typer.Exit(code=1)

    console.print("[bold]Loading profiles...[/bold]")
    baseline = load_profile(BASELINE_PATH)
    target = load_profile(TARGET_PATH)

    console.print("[bold]Running differential engine (Phase 3)...[/bold]")
    raw_diffs = compare_profiles(baseline, target)
    console.print(f"  {len(raw_diffs)} raw differences detected.")

    console.print("[bold]Classifying differences (Phase 4) and ranking (Phase 5)...[/bold]")
    findings = build_findings(raw_diffs)

    saved_path = save_diff_results(findings, baseline.identity, target.identity, DIFF_RESULTS_PATH)
    console.print(f"[green]Saved:[/green] {saved_path}")

    console.print()
    _print_findings_table(findings, limit=20)

    if not no_report:
        console.print()
        console.print("[bold]Generating reports (Phase 6)...[/bold]")
        paths = generate_all(findings, baseline.identity, target.identity, OUTPUT_DIR)
        for fmt, p in paths.items():
            console.print(f"  {fmt:9s} -> {p}")

    fp_count = sum(1 for f in findings if f.risk_score.likely_false_positive)
    console.print()
    console.print(
        f"[bold]{len(findings)}[/bold] total investigation candidates "
        f"([dim]{fp_count} flagged as likely false positives[/dim]). "
        "All require manual verification -- none are confirmed vulnerabilities."
    )


@app.command("report")
def report() -> None:
    """(Re)generate Markdown/HTML/JSON reports from the last `compare` run,
    without recomputing the diff."""
    setup_logging()
    try:
        baseline_identity, target_identity, findings = load_diff_results(DIFF_RESULTS_PATH)
    except BossAuditorError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc

    paths = generate_all(findings, baseline_identity, target_identity, OUTPUT_DIR)
    console.print("[green]Reports generated:[/green]")
    for fmt, p in paths.items():
        console.print(f"  {fmt:9s} -> {p}")


@app.command("top20")
def top20() -> None:
    """Print the top 20 findings from the last `compare` run."""
    setup_logging()
    try:
        _, _, findings = load_diff_results(DIFF_RESULTS_PATH)
    except BossAuditorError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc

    _print_findings_table(findings, limit=20)


if __name__ == "__main__":
    app()
