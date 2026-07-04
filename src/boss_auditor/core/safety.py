"""Structural enforcement of the "read-only, non-destructive, non-exploitative"
contract described in `core.constants`.

Design principle: **default-deny, allow-list only.** Rather than trying to
blacklist every dangerous flag (which is easy to bypass), every collector
plugin must route external commands through `assert_safe_command()`, which
only permits a curated set of binaries, and only in their read-only
sub-command / flag forms. Anything not explicitly recognized is rejected.

This module intentionally contains no logic for *running* commands -- only
for deciding whether a proposed command is allowed to run. Execution lives
in `core.process`, and always calls this validator first.
"""

from __future__ import annotations

from dataclasses import dataclass

from boss_auditor.core.exceptions import UnsafeOperationError

# Bare words/flags that are never acceptable, regardless of which binary
# they appear on. These are the generic "mutate / destroy / stress" verbs.
# Deliberately does NOT include flags that are ambiguous across binaries
# (e.g. `-a` means "all" for uname/sysctl but "append" for iptables) --
# those are instead scoped per-binary via `_ALLOWED_BINARIES` below.
_GLOBAL_DENY_TOKENS: frozenset[str] = frozenset(
    {
        # mutation / deletion
        "rm", "-rf", "--force", "delete", "-delete", "del", "remove",
        "purge", "mkfs", "dd", "shred", "wipefs", "truncate",
        # privilege / account mutation
        "useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd",
        "chpasswd", "visudo",
        # permission / ownership mutation
        "chmod", "chown", "chattr", "setfacl", "setcap",
        # service / unit mutation
        "start", "stop", "restart", "reload", "enable", "disable", "mask",
        "unmask", "kill",
        # package mutation
        "install", "uninstall", "reinstall", "autoremove",
        # arbitrary code execution flags on otherwise-safe binaries (e.g.
        # `find ... -exec ...`)
        "-exec", "-execdir", "-ok", "-okdir",
        # exploitation / offensive tooling (never permitted, ever)
        "msfconsole", "msfvenom", "sqlmap", "hydra", "medusa", "john",
        "hashcat", "nmap", "exploit", "payload", "reverse_shell",
        # write-mode redirection markers should never be constructed by
        # plugin code
        ">", ">>",
    }
)

# binary -> allowed first-subcommand-or-flag set. `None` means "any flags
# are fine as long as no global-deny token is present" (used for pure
# read/list/status binaries that have no write mode at all).
_ALLOWED_BINARIES: dict[str, frozenset[str] | None] = {
    "uname": None,
    "hostnamectl": frozenset({"status"}),
    "cat": None,
    "ls": None,
    "stat": None,
    "file": None,
    "readlink": None,
    "find": None,  # NOTE: -delete / -exec are still blocked via deny tokens
    "getfacl": None,
    "id": None,
    "whoami": None,
    "groups": None,
    "getent": None,
    "dpkg": frozenset({"-l", "--list", "-s", "--status", "-L", "--listfiles"}),
    "dpkg-query": None,
    "apt-cache": frozenset({"policy", "show", "search", "depends"}),
    "apt-config": frozenset({"dump"}),
    "systemctl": frozenset(
        {
            "status", "list-units", "list-unit-files", "show", "is-enabled",
            "is-active", "cat", "list-timers", "list-sockets",
        }
    ),
    "journalctl": None,
    "loginctl": frozenset({"list-sessions", "list-users", "show-session", "show-user"}),
    "busctl": frozenset({"list", "tree", "status"}),
    "ss": None,
    "netstat": None,
    "ip": frozenset({"addr", "link", "route", "-s"}),
    "sysctl": frozenset({"-a", "--all"}),  # read-all only, never -w
    "mount": None,  # bare `mount` lists; no target args expected from plugins
    "findmnt": None,
    "lsblk": None,
    "lsmod": None,
    "modinfo": None,
    "getcap": None,
    "capsh": frozenset({"--print"}),
    "getenforce": None,
    "sestatus": None,
    "aa-status": None,
    "apparmor_status": None,
    "auditctl": frozenset({"-l", "--list"}),
    "crontab": frozenset({"-l"}),
    "gpg": frozenset({"--list-keys", "--list-secret-keys"}),
    "sha256sum": None,
    "md5sum": None,
    "efibootmgr": None,  # bare call is read-only
    "ufw": frozenset({"status"}),
    "firewall-cmd": frozenset({"--list-all", "--list-all-zones", "--state"}),
    "iptables": frozenset({"-L", "-S", "-n", "-v"}),
    "iptables-save": None,
    "docker": frozenset({"ps", "images", "inspect", "info", "version"}),
    "podman": frozenset({"ps", "images", "inspect", "info", "version"}),
    "pam-auth-update": frozenset({"--list"}),
    "env": None,
    "printenv": None,
    "who": None,
    "last": None,
    "lastlog": None,
    "ps": None,  # process listing has no destructive invocation form
}


@dataclass(frozen=True, slots=True)
class SafeCommand:
    """A validated command ready for execution."""

    argv: tuple[str, ...]


def assert_safe_command(argv: list[str] | tuple[str, ...]) -> SafeCommand:
    """Validate that `argv` is an allowed read-only command.

    Raises `UnsafeOperationError` if the binary is not on the allow-list, or
    if any token matches a globally denied mutating/offensive verb.

    This performs no shell interpretation -- argv must already be a list of
    literal tokens (never pass `shell=True` strings into this framework).
    """
    if not argv:
        raise UnsafeOperationError("Empty command is not valid.")

    binary = argv[0].rsplit("/", 1)[-1]

    if binary not in _ALLOWED_BINARIES:
        raise UnsafeOperationError(
            f"Binary '{binary}' is not on the read-only allow-list. "
            "Add it to core.safety._ALLOWED_BINARIES only if it has a "
            "genuinely read-only invocation, and scope the allowed flags "
            "explicitly."
        )

    tokens = [tok.lower() for tok in argv[1:]]
    denied = set(tokens) & _GLOBAL_DENY_TOKENS
    if denied:
        raise UnsafeOperationError(
            f"Command '{' '.join(argv)}' contains disallowed token(s): "
            f"{sorted(denied)}. Only read-only invocations are permitted."
        )

    allowed_subcommands = _ALLOWED_BINARIES[binary]
    if allowed_subcommands is not None and argv[1:]:
        # Two shapes of allow-list, auto-detected:
        #   * "flag-style" (e.g. dpkg -l, iptables -L): every entry starts
        #     with '-'. Every dash-prefixed token in the command must be in
        #     the allow-list; bare arguments (package names, etc.) pass
        #     through untouched.
        #   * "subcommand-style" (e.g. systemctl status, docker ps): entries
        #     are bare words. Only the *first* token must be an allowed
        #     subcommand; everything after it is an argument to that
        #     subcommand (a unit name, container id, etc.), already covered
        #     by the global deny-token check above.
        is_flag_style = all(entry.startswith("-") for entry in allowed_subcommands)

        if is_flag_style:
            for tok in argv[1:]:
                if tok.startswith("-") and tok not in allowed_subcommands:
                    raise UnsafeOperationError(
                        f"'{binary} {tok}' is not an approved read-only flag. "
                        f"Approved for '{binary}': {sorted(allowed_subcommands)}"
                    )
        else:
            first_arg = argv[1]
            if first_arg not in allowed_subcommands:
                raise UnsafeOperationError(
                    f"'{binary} {first_arg}' is not an approved read-only "
                    f"sub-command. Approved for '{binary}': "
                    f"{sorted(allowed_subcommands)}"
                )

    return SafeCommand(argv=tuple(argv))
