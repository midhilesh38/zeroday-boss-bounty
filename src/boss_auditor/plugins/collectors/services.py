"""Collects systemd service unit states and currently-running services.
New/removed/re-enabled services are high-signal for both attack surface
and persistence, so this section gets specific attention in Phase 4/5."""

from __future__ import annotations

from boss_auditor.core.process import run_safe
from boss_auditor.plugins.base import CollectorPlugin


class ServicesCollector(CollectorPlugin):
    name = "services"
    section = "services"
    description = "systemd service unit-file states and running services."
    timeout_seconds = 20

    def collect(self) -> dict:
        data: dict = {}

        unit_files: dict[str, str] = {}
        result = run_safe(
            ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                unit_files[parts[0]] = parts[1]
        data["unit_files"] = unit_files

        running: list[str] = []
        result = run_safe(
            [
                "systemctl", "list-units", "--type=service", "--state=running",
                "--no-legend", "--no-pager",
            ]
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts:
                running.append(parts[0])
        data["running_services"] = sorted(set(running))

        return data
