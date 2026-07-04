from __future__ import annotations

import pytest

from boss_auditor.core.exceptions import UnsafeOperationError
from boss_auditor.core.safety import assert_safe_command


def test_allows_known_readonly_command() -> None:
    cmd = assert_safe_command(["uname", "-a"])
    assert cmd.argv == ("uname", "-a")


def test_allows_dpkg_list() -> None:
    cmd = assert_safe_command(["dpkg", "-l"])
    assert cmd.argv == ("dpkg", "-l")


def test_rejects_unknown_binary() -> None:
    with pytest.raises(UnsafeOperationError):
        assert_safe_command(["curl", "http://example.com"])


def test_rejects_mutating_systemctl_verb() -> None:
    with pytest.raises(UnsafeOperationError):
        assert_safe_command(["systemctl", "restart", "ssh"])


def test_allows_readonly_systemctl_verb() -> None:
    cmd = assert_safe_command(["systemctl", "status", "ssh"])
    assert cmd.argv[1] == "status"


def test_rejects_find_delete() -> None:
    with pytest.raises(UnsafeOperationError):
        assert_safe_command(["find", "/tmp", "-name", "*.log", "-delete"])


def test_rejects_offensive_tooling() -> None:
    with pytest.raises(UnsafeOperationError):
        assert_safe_command(["nmap", "-sV", "127.0.0.1"])


def test_rejects_empty_command() -> None:
    with pytest.raises(UnsafeOperationError):
        assert_safe_command([])


def test_rejects_iptables_mutation() -> None:
    with pytest.raises(UnsafeOperationError):
        assert_safe_command(["iptables", "-A", "INPUT", "-j", "DROP"])


def test_allows_iptables_list() -> None:
    cmd = assert_safe_command(["iptables", "-L", "-n"])
    assert cmd.argv[1] == "-L"
