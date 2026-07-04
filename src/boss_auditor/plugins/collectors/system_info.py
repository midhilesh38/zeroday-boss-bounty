"""Collects basic, low-risk system identity facts: kernel, OS release,
architecture, hostname. Entirely read-only file reads and `uname`."""

from __future__ import annotations

from pathlib import Path

from boss_auditor.core.process import run_safe
from boss_auditor.plugins.base import CollectorPlugin


class SystemInfoCollector(CollectorPlugin):
    name = "system_info"
    section = "system"
    description = "Kernel version, OS release, architecture, hostname."

    def collect(self) -> dict:
        data: dict = {}

        uname = run_safe(["uname", "-a"])
        data["uname"] = uname.stdout.strip()

        kernel = run_safe(["uname", "-r"])
        data["kernel_release"] = kernel.stdout.strip()

        arch = run_safe(["uname", "-m"])
        data["architecture"] = arch.stdout.strip()

        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            fields = {}
            for line in os_release_path.read_text(encoding="utf-8").splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    fields[key] = value.strip('"')
            data["os_release"] = fields
        else:
            data["os_release"] = {}

        hostname_path = Path("/etc/hostname")
        data["hostname"] = (
            hostname_path.read_text(encoding="utf-8").strip()
            if hostname_path.exists()
            else None
        )

        machine_id_path = Path("/etc/machine-id")
        data["has_machine_id"] = machine_id_path.exists()

        return data
