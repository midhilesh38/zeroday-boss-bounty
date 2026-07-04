"""Collects a snapshot of running process command lines.

Deliberately excludes PID/PPID: those are ephemeral and differ on every
boot even with identical software, so including them would make every
single scan look like a wall of differences. What's actually comparable
between baseline and target is *which programs run as which users* --
so we capture (user, command) pairs, deduplicated and sorted.
"""

from __future__ import annotations

from boss_auditor.core.process import run_safe
from boss_auditor.plugins.base import CollectorPlugin


class ProcessListCollector(CollectorPlugin):
    name = "processes"
    section = "processes"
    description = "Deduplicated (user, command) pairs from the process table."

    def collect(self) -> dict:
        result = run_safe(["ps", "-eo", "user,comm", "--no-headers"], timeout=10)
        entries: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                entries.add(line)
        return {"process_signatures": sorted(entries)}
