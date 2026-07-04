"""BOSS Differential Security Auditor -- command line interface.

Phase 1 scope: scan a host and store a structured JSON profile
(`scan`), and inspect what collectors are registered (`list-plugins`).
Comparison, reporting, and the web dashboard are later phases.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from boss_auditor.core.config import load_config
from boss_auditor.core.constants import (
    BASELINE_PROFILE_NAME,
    DEFAULT_CONFIG_PATH,
    TARGET_PROFILE_NAME,
)
from boss_auditor.core.logging import setup_logging
from boss_auditor.core.models import SystemIdentity
from boss_auditor.core.profile_store import save_profile
from boss_auditor.plugins.registry import get_registry

app = typer.Typer(
    name="boss-auditor",
    help="Read-only differential security auditor: Debian 13 baseline vs. BOSS OS target.",
    add_completion=False,
)
console = Console()


@app.command("list-plugins")
def list_plugins(
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", "-c"),
) -> None:
    """Show every registered collector plugin and whether it's enabled."""
    setup_logging()
    config = load_config(config_path)
    registry = get_registry()

    table = Table(title="Registered Collector Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Section", style="magenta")
    table.add_column("Enabled", style="green")
    table.add_column("Description")

    for plugin_cls in sorted(registry.all_plugins(), key=lambda p: p.name):
        enabled = "yes" if config.is_plugin_enabled(plugin_cls.name) else "no"
        table.add_row(plugin_cls.name, plugin_cls.section, enabled, plugin_cls.description)

    console.print(table)


@app.command("scan")
def scan(
    label: str = typer.Argument(..., help="Identity label, e.g. 'baseline' or 'target'."),
    output: Path = typer.Option(
        None, "--output", "-o", help="Where to write the JSON profile."
    ),
    config_path: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", "-c"),
) -> None:
    """Run all enabled collector plugins against the current host and save
    a structured JSON profile. Run this once on a clean Debian 13 baseline
    (label='baseline') and once on the BOSS OS target (label='target')."""
    setup_logging()
    config = load_config(config_path)
    registry = get_registry()

    identity = SystemIdentity(label=label)

    console.print(f"[bold]Scanning host[/bold] -- label={label!r}")
    profile = registry.run_all(identity=identity, config=config)

    if output is None:
        default_name = BASELINE_PROFILE_NAME if label == "baseline" else TARGET_PROFILE_NAME
        output = config.profile_dir / default_name

    saved_path = save_profile(profile, output)

    summary = profile.summary()
    ok = sum(1 for s in summary.values() if s == "ok")
    console.print(
        f"[green]Done.[/green] {ok}/{len(summary)} sections collected successfully."
    )
    console.print(f"Profile saved to: [bold]{saved_path}[/bold]")


if __name__ == "__main__":
    app()
