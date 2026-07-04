"""Exception hierarchy for BOSS Differential Security Auditor."""

from __future__ import annotations


class BossAuditorError(Exception):
    """Base class for all framework errors."""


class PluginError(BossAuditorError):
    """Raised when a plugin fails to execute or is malformed."""


class UnsafeOperationError(BossAuditorError):
    """Raised when a plugin (or a command it wants to run) violates the
    read-only / non-destructive / non-exploitative safety contract.

    This is a hard stop -- it must never be caught and silently ignored by
    calling code outside of tests.
    """


class ProfileError(BossAuditorError):
    """Raised for problems loading, saving, or validating a system profile."""


class ConfigError(BossAuditorError):
    """Raised for problems loading or validating framework configuration."""


class ComparisonError(BossAuditorError):
    """Raised when the differential engine cannot compare two profiles."""
