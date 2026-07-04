"""Collects sshd configuration directives from /etc/ssh/sshd_config and any
Debian-style /etc/ssh/sshd_config.d/*.conf includes. Pure file reads."""

from __future__ import annotations

from pathlib import Path

from boss_auditor.plugins.base import CollectorPlugin

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")


def _parse_sshd_config(text: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            directives[key] = value
    return directives


class SshConfigCollector(CollectorPlugin):
    name = "ssh_config"
    section = "ssh_config"
    description = "sshd_config directives, including sshd_config.d includes."

    def collect(self) -> dict:
        directives: dict[str, str] = {}
        included_files: list[str] = []

        if SSHD_CONFIG.is_file():
            directives.update(
                _parse_sshd_config(SSHD_CONFIG.read_text(encoding="utf-8", errors="replace"))
            )

        if SSHD_CONFIG_D.is_dir():
            for f in sorted(SSHD_CONFIG_D.glob("*.conf")):
                included_files.append(f.name)
                directives.update(
                    _parse_sshd_config(f.read_text(encoding="utf-8", errors="replace"))
                )

        return {"directives": directives, "included_files": included_files}
