"""Collects all readable sysctl kernel parameters via `sysctl -a`."""

from __future__ import annotations

from boss_auditor.core.process import run_safe
from boss_auditor.plugins.base import CollectorPlugin


class SysctlCollector(CollectorPlugin):
    name = "sysctl"
    section = "sysctl"
    description = "Kernel parameters as reported by `sysctl -a`."
    timeout_seconds = 20

    def collect(self) -> dict:
        result = run_safe(["sysctl", "-a"], timeout=20)
        params: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            params[key.strip()] = value.strip()
        return {"parameters": params, "parameter_count": len(params)}
