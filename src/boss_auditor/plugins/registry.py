"""Plugin discovery, registration, and orchestrated execution.

Collector plugins live in `boss_auditor/plugins/collectors/` as modules
each exposing one or more `CollectorPlugin` subclasses. The registry
auto-discovers them, so adding a new collector never requires touching
this file.
"""

from __future__ import annotations

import importlib
import pkgutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from boss_auditor.core.config import AppConfig
from boss_auditor.core.exceptions import PluginError
from boss_auditor.core.logging import get_logger
from boss_auditor.core.models import SystemIdentity, SystemProfile
from boss_auditor.plugins import collectors as collectors_package
from boss_auditor.plugins.base import CollectorPlugin, require_attrs

logger = get_logger()


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[CollectorPlugin]] = {}

    def register(self, plugin_cls: type[CollectorPlugin]) -> None:
        require_attrs(plugin_cls)
        if plugin_cls.name in self._plugins:
            raise PluginError(f"Duplicate plugin name registered: {plugin_cls.name!r}")
        self._plugins[plugin_cls.name] = plugin_cls
        logger.debug("Registered plugin: %s (section=%s)", plugin_cls.name, plugin_cls.section)

    def discover(self) -> None:
        """Import every module under `plugins/collectors/` and register any
        `CollectorPlugin` subclasses found in it."""
        for _, module_name, _ in pkgutil.iter_modules(collectors_package.__path__):
            module = importlib.import_module(
                f"{collectors_package.__name__}.{module_name}"
            )
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, CollectorPlugin)
                    and attr is not CollectorPlugin
                ):
                    if attr.name not in self._plugins:
                        self.register(attr)

    def get(self, name: str) -> type[CollectorPlugin]:
        try:
            return self._plugins[name]
        except KeyError as exc:
            raise PluginError(f"No such plugin registered: {name!r}") from exc

    def all_plugins(self) -> list[type[CollectorPlugin]]:
        return list(self._plugins.values())

    def enabled_plugins(self, config: AppConfig) -> list[type[CollectorPlugin]]:
        return [p for p in self.all_plugins() if config.is_plugin_enabled(p.name)]

    def run_all(
        self,
        *,
        identity: SystemIdentity,
        config: AppConfig,
        max_workers: int = 8,
    ) -> SystemProfile:
        """Execute every enabled plugin (concurrently, I/O-bound so threads
        are the right primitive here) and assemble a `SystemProfile`."""
        profile = SystemProfile(identity=identity)
        plugin_classes = self.enabled_plugins(config)

        if not plugin_classes:
            logger.warning("No plugins are enabled -- profile will be empty.")
            return profile

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_name = {
                pool.submit(plugin_cls().run): plugin_cls.name
                for plugin_cls in plugin_classes
            }
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - defensive, run() already isolates
                    logger.error("Unexpected error running plugin '%s': %s", name, exc)
                    continue
                profile.add_result(result)
                logger.info(
                    "[%s] %s -> %s (%.3fs)",
                    result.status.value.upper(),
                    name,
                    result.section,
                    result.duration_seconds,
                )

        return profile


_default_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    """Return a process-wide registry with all collectors discovered."""
    global _default_registry
    if _default_registry is None:
        _default_registry = PluginRegistry()
        _default_registry.discover()
    return _default_registry
