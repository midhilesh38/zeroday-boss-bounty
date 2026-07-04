from __future__ import annotations

from boss_auditor.core.config import AppConfig
from boss_auditor.core.models import CollectionStatus, SystemIdentity
from boss_auditor.plugins.base import CollectorPlugin
from boss_auditor.plugins.registry import PluginRegistry, get_registry


class _DummyPlugin(CollectorPlugin):
    name = "dummy"
    section = "dummy_section"
    description = "test plugin"

    def collect(self) -> dict:
        return {"hello": "world"}


class _FailingPlugin(CollectorPlugin):
    name = "dummy_failing"
    section = "dummy_failing_section"

    def collect(self) -> dict:
        raise RuntimeError("boom")


def test_register_and_run_single_plugin() -> None:
    registry = PluginRegistry()
    registry.register(_DummyPlugin)

    config = AppConfig()
    identity = SystemIdentity(label="test")
    profile = registry.run_all(identity=identity, config=config)

    assert "dummy_section" in profile.sections
    result = profile.sections["dummy_section"]
    assert result.status == CollectionStatus.OK
    assert result.data == {"hello": "world"}


def test_failing_plugin_does_not_crash_run_all() -> None:
    registry = PluginRegistry()
    registry.register(_DummyPlugin)
    registry.register(_FailingPlugin)

    config = AppConfig()
    identity = SystemIdentity(label="test")
    profile = registry.run_all(identity=identity, config=config)

    assert profile.sections["dummy_section"].status == CollectionStatus.OK
    assert profile.sections["dummy_failing_section"].status == CollectionStatus.FAILED
    assert profile.sections["dummy_failing_section"].errors


def test_disabled_plugin_is_skipped() -> None:
    registry = PluginRegistry()
    registry.register(_DummyPlugin)

    config = AppConfig(disabled_plugins=["dummy"])
    identity = SystemIdentity(label="test")
    profile = registry.run_all(identity=identity, config=config)

    assert "dummy_section" not in profile.sections


def test_real_collectors_discovered() -> None:
    registry = get_registry()
    names = {p.name for p in registry.all_plugins()}
    assert "system_info" in names
    assert "installed_packages" in names
