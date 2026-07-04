"""Collects the installed package list and configured APT repositories.
This is one of the highest-signal sections for the future differential
engine -- new/removed/modified packages between baseline and target are
often the first clue something was changed."""

from __future__ import annotations

from pathlib import Path

from boss_auditor.core.process import run_safe
from boss_auditor.plugins.base import CollectorPlugin


class InstalledPackagesCollector(CollectorPlugin):
    name = "installed_packages"
    section = "packages"
    description = "dpkg-installed packages with versions, plus APT sources."
    timeout_seconds = 30

    def collect(self) -> dict:
        data: dict = {}

        result = run_safe(["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\t${Status}\\n"])
        packages: dict[str, dict[str, str]] = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                pkg, version, status = parts
                packages[pkg] = {"version": version, "status": status}
        data["packages"] = packages
        data["package_count"] = len(packages)

        sources_list = Path("/etc/apt/sources.list")
        sources_dir = Path("/etc/apt/sources.list.d")

        repo_lines: list[str] = []
        if sources_list.exists():
            repo_lines.extend(
                line.strip()
                for line in sources_list.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
        if sources_dir.exists():
            for f in sorted(sources_dir.glob("*")):
                if f.is_file():
                    repo_lines.extend(
                        f"[{f.name}] {line.strip()}"
                        for line in f.read_text(encoding="utf-8", errors="replace").splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    )
        data["apt_repositories"] = repo_lines

        return data
