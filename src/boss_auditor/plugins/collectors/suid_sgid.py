"""Inventories SUID and SGID binaries on the root filesystem.

This is one of the highest-signal sections for the differential engine: a
new SUID binary that wasn't present on the clean baseline is one of the
most common ways a modified OS image introduces a privilege-escalation
path. `-xdev` keeps the scan confined to the root filesystem (no crossing
into /proc, tmpfs, or other mounted filesystems), keeping this fast and
read-only.
"""

from __future__ import annotations

from boss_auditor.core.process import run_safe
from boss_auditor.plugins.base import CollectorPlugin


class SuidSgidCollector(CollectorPlugin):
    name = "suid_sgid"
    section = "suid_sgid"
    description = "SUID and SGID binaries found on the root filesystem."
    timeout_seconds = 60

    def collect(self) -> dict:
        data: dict = {}

        suid = run_safe(["find", "/", "-xdev", "-type", "f", "-perm", "-4000"], timeout=60)
        data["suid_files"] = sorted(
            line.strip() for line in suid.stdout.splitlines() if line.strip()
        )
        if suid.timed_out:
            data["suid_scan_timed_out"] = True

        sgid = run_safe(["find", "/", "-xdev", "-type", "f", "-perm", "-2000"], timeout=60)
        data["sgid_files"] = sorted(
            line.strip() for line in sgid.stdout.splitlines() if line.strip()
        )
        if sgid.timed_out:
            data["sgid_scan_timed_out"] = True

        return data
