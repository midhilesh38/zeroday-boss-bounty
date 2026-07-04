"""Collects the contents of every file under /etc/pam.d.

PAM stack changes are structurally significant: they govern authentication
and authorization decisions across the whole system, so this section is
treated as high-signal in Phase 4 regardless of which specific line
changed. Pure file reads -- no subprocess needed."""

from __future__ import annotations

from pathlib import Path

from boss_auditor.plugins.base import CollectorPlugin

PAM_DIR = Path("/etc/pam.d")


class PamCollector(CollectorPlugin):
    name = "pam"
    section = "pam"
    description = "Contents of /etc/pam.d/* configuration files."

    def collect(self) -> dict:
        files: dict[str, list[str]] = {}
        if PAM_DIR.is_dir():
            for f in sorted(PAM_DIR.glob("*")):
                if not f.is_file():
                    continue
                lines = [
                    line.strip()
                    for line in f.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                files[f.name] = lines
        return {"pam_files": files, "pam_file_count": len(files)}
