"""Checks permissions and ownership on a curated list of security-sensitive
paths. Uses `os.stat` directly -- no subprocess needed, so this can't be
blocked or slowed down by the safety allow-list, and can't accidentally
shell out to anything."""

from __future__ import annotations

import stat as _stat
from pathlib import Path

from boss_auditor.plugins.base import CollectorPlugin

SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/cron.d",
    "/root",
    "/boot/grub/grub.cfg",
]


class FilePermissionsCollector(CollectorPlugin):
    name = "file_permissions"
    section = "file_permissions"
    description = "Permissions/ownership on a curated set of sensitive paths."

    def collect(self) -> dict:
        results: dict[str, dict] = {}
        for path_str in SENSITIVE_PATHS:
            path = Path(path_str)
            if not path.exists():
                results[path_str] = {"exists": False}
                continue
            try:
                st = path.stat()
            except PermissionError:
                results[path_str] = {"exists": True, "error": "permission_denied"}
                continue
            results[path_str] = {
                "exists": True,
                "mode": oct(_stat.S_IMODE(st.st_mode)),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "is_world_writable": bool(st.st_mode & 0o002),
                "is_world_readable": bool(st.st_mode & 0o004),
            }
        return {"sensitive_paths": results}
