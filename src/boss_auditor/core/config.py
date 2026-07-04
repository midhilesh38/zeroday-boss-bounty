"""Framework configuration.

Config is plain YAML on disk, loaded into a validated Pydantic model. Kept
deliberately simple in Phase 1 -- only the settings the collector/plugin
layer needs right now. Later phases (reporting, dashboard) will extend
`AppConfig` rather than replace it.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from boss_auditor.core.constants import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PLUGIN_TIMEOUT_SECONDS,
    DEFAULT_PROFILE_DIR,
)
from boss_auditor.core.exceptions import ConfigError


class PluginConfig(BaseModel):
    enabled: bool = True
    timeout_seconds: int = DEFAULT_PLUGIN_TIMEOUT_SECONDS


class AppConfig(BaseModel):
    profile_dir: Path = DEFAULT_PROFILE_DIR
    output_dir: Path = DEFAULT_OUTPUT_DIR
    log_level: str = "INFO"
    plugins: dict[str, PluginConfig] = Field(default_factory=dict)
    disabled_plugins: list[str] = Field(default_factory=list)

    def plugin_config(self, plugin_name: str) -> PluginConfig:
        return self.plugins.get(plugin_name, PluginConfig())

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        if plugin_name in self.disabled_plugins:
            return False
        return self.plugin_config(plugin_name).enabled


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> AppConfig:
    """Load config from YAML, falling back to defaults if the file doesn't
    exist yet (a fresh checkout should still run)."""
    path = Path(path)
    if not path.exists():
        return AppConfig()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse config at {path}: {exc}") from exc

    try:
        return AppConfig.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError, kept generic here
        raise ConfigError(f"Invalid config at {path}: {exc}") from exc
