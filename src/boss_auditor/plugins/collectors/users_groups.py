"""Parses /etc/passwd and /etc/group. Pure file reads -- no subprocess.

New UID-0 accounts and membership changes in privileged groups (sudo,
wheel, adm, disk, docker) are the highest-signal differences in this
section for the Phase 4 classifier."""

from __future__ import annotations

from pathlib import Path

from boss_auditor.plugins.base import CollectorPlugin

PASSWD_PATH = Path("/etc/passwd")
GROUP_PATH = Path("/etc/group")


class UsersGroupsCollector(CollectorPlugin):
    name = "users_groups"
    section = "users_groups"
    description = "Local user accounts (/etc/passwd) and groups (/etc/group)."

    def collect(self) -> dict:
        users: dict[str, dict] = {}
        if PASSWD_PATH.is_file():
            for line in PASSWD_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                fields = line.split(":")
                if len(fields) >= 7:
                    name, _, uid, gid, gecos, home, shell = fields[:7]
                    users[name] = {
                        "uid": uid,
                        "gid": gid,
                        "home": home,
                        "shell": shell,
                    }

        groups: dict[str, dict] = {}
        if GROUP_PATH.is_file():
            for line in GROUP_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                fields = line.split(":")
                if len(fields) >= 4:
                    name, _, gid, members = fields[:4]
                    groups[name] = {
                        "gid": gid,
                        "members": sorted(m for m in members.split(",") if m),
                    }

        return {"users": users, "groups": groups}
