"""The only sanctioned way for plugins to shell out to the host system.

Every call goes through `core.safety.assert_safe_command` first. Commands
are always run as an argv list (never `shell=True`), always time-boxed, and
never retried automatically.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from boss_auditor.core.constants import DEFAULT_PLUGIN_TIMEOUT_SECONDS
from boss_auditor.core.safety import assert_safe_command


@dataclass(slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_safe(
    argv: list[str] | tuple[str, ...],
    *,
    timeout: int = DEFAULT_PLUGIN_TIMEOUT_SECONDS,
) -> CommandResult:
    """Validate and execute a read-only command, capturing its output.

    Never raises on a non-zero exit code (many read-only introspection
    commands legitimately return non-zero, e.g. `systemctl is-active` on a
    stopped unit) -- callers should inspect `returncode`. Does raise
    `UnsafeOperationError` if the command fails the safety allow-list.
    """
    safe = assert_safe_command(argv)

    try:
        completed = subprocess.run(  # noqa: S603 - argv validated above
            safe.argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            argv=safe.argv, returncode=-1, stdout="", stderr="timed out", timed_out=True
        )
    except FileNotFoundError:
        return CommandResult(
            argv=safe.argv,
            returncode=127,
            stdout="",
            stderr=f"binary not found: {safe.argv[0]}",
        )

    return CommandResult(
        argv=safe.argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
