"""Base class for all collector plugins.

A plugin's `collect()` method must be pure evidence-gathering: it may read
files, and it may run commands via `core.process.run_safe` (which enforces
the read-only allow-list from `core.safety`). It must never write, delete,
or mutate anything on the host, and must never take longer than its
declared timeout.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from boss_auditor.core.exceptions import PluginError, UnsafeOperationError
from boss_auditor.core.logging import get_logger
from boss_auditor.core.models import CollectionStatus, PluginResult

logger = get_logger()


class CollectorPlugin(ABC):
    """Subclass this for every new data-collection module.

    Required class attributes:
        name: unique machine-readable identifier, e.g. "installed_packages"
        section: the profile section this plugin populates, e.g. "packages"
        description: one-line human-readable summary

    Implement `collect()` to return a plain JSON-serializable dict. Do not
    catch `UnsafeOperationError` -- let it propagate; the plugin manager
    treats it as a hard failure for that plugin only, and continues with
    the rest of the scan.
    """

    name: str
    section: str
    description: str = ""
    timeout_seconds: int = 15

    @abstractmethod
    def collect(self) -> dict:
        """Gather evidence and return a JSON-serializable dict."""
        raise NotImplementedError

    def run(self) -> PluginResult:
        """Wraps `collect()` with timing, error handling, and status
        classification. This is what the plugin manager calls -- plugins
        should not need to override it."""
        start = time.monotonic()
        try:
            data = self.collect()
            status = CollectionStatus.OK
            errors: list[str] = []
        except UnsafeOperationError as exc:
            # A plugin tried to do something outside the read-only
            # contract. This is a bug in the plugin, not a transient
            # failure -- surface it loudly rather than swallowing it.
            logger.error(
                "[bold red]Plugin '%s' attempted an unsafe operation: %s[/bold red]",
                self.name,
                exc,
            )
            data = {}
            status = CollectionStatus.SKIPPED_UNSAFE
            errors = [str(exc)]
        except Exception as exc:  # noqa: BLE001 - isolate plugin failures
            logger.warning("Plugin '%s' failed: %s", self.name, exc)
            data = {}
            status = CollectionStatus.FAILED
            errors = [str(exc)]

        duration = time.monotonic() - start
        return PluginResult(
            plugin_name=self.name,
            section=self.section,
            status=status,
            data=data,
            errors=errors,
            duration_seconds=round(duration, 4),
        )

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<CollectorPlugin {self.name!r} section={self.section!r}>"


def require_attrs(plugin_cls: type[CollectorPlugin]) -> None:
    """Validate that a plugin class defines the required identity
    attributes before it's allowed into the registry."""
    for attr in ("name", "section"):
        if not getattr(plugin_cls, attr, None):
            raise PluginError(
                f"Plugin class {plugin_cls.__name__} is missing required "
                f"attribute '{attr}'."
            )
