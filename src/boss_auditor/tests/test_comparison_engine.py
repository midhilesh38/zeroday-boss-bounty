from __future__ import annotations

from boss_auditor.comparison.engine import compare_profiles
from boss_auditor.core.models import (
    ChangeType,
    CollectionStatus,
    PluginResult,
    SystemIdentity,
    SystemProfile,
)


def _profile(label: str, sections: dict[str, dict]) -> SystemProfile:
    profile = SystemProfile(identity=SystemIdentity(label=label))
    for section, data in sections.items():
        profile.add_result(
            PluginResult(
                plugin_name=section, section=section, status=CollectionStatus.OK, data=data
            )
        )
    return profile


def test_new_package_detected() -> None:
    baseline = _profile("baseline", {"packages": {"packages": {"curl": {"version": "1.0"}}}})
    target = _profile(
        "target",
        {"packages": {"packages": {"curl": {"version": "1.0"}, "netcat": {"version": "2.0"}}}},
    )
    diffs = compare_profiles(baseline, target)
    new_pkg = [d for d in diffs if d.path == "packages.netcat"]
    assert len(new_pkg) == 1
    assert new_pkg[0].change_type == ChangeType.NEW
    assert new_pkg[0].target_value == {"version": "2.0"}


def test_removed_package_detected() -> None:
    baseline = _profile("baseline", {"packages": {"packages": {"auditd": {"version": "1.0"}}}})
    target = _profile("target", {"packages": {"packages": {}}})
    diffs = compare_profiles(baseline, target)
    removed = [d for d in diffs if d.path == "packages.auditd"]
    assert len(removed) == 1
    assert removed[0].change_type == ChangeType.REMOVED


def test_version_modification_detected() -> None:
    baseline = _profile("baseline", {"packages": {"packages": {"openssh-server": {"version": "1.0"}}}})
    target = _profile("target", {"packages": {"packages": {"openssh-server": {"version": "0.9"}}}})
    diffs = compare_profiles(baseline, target)
    modified = [d for d in diffs if d.path == "packages.openssh-server.version"]
    assert len(modified) == 1
    assert modified[0].change_type == ChangeType.MODIFIED
    assert modified[0].baseline_value == "1.0"
    assert modified[0].target_value == "0.9"


def test_suid_list_set_diff() -> None:
    baseline = _profile("baseline", {"suid_sgid": {"suid_files": ["/usr/bin/passwd"]}})
    target = _profile(
        "target",
        {"suid_sgid": {"suid_files": ["/usr/bin/passwd", "/usr/local/bin/backdoor"]}},
    )
    diffs = compare_profiles(baseline, target)
    new_suid = [d for d in diffs if d.change_type == ChangeType.NEW]
    assert len(new_suid) == 1
    assert new_suid[0].target_value == "/usr/local/bin/backdoor"


def test_identical_sections_produce_no_diff() -> None:
    baseline = _profile("baseline", {"system": {"kernel_release": "6.1.0"}})
    target = _profile("target", {"system": {"kernel_release": "6.1.0"}})
    assert compare_profiles(baseline, target) == []


def test_excluded_derived_key_ignored() -> None:
    baseline = _profile("baseline", {"packages": {"packages": {}, "package_count": 0}})
    target = _profile("target", {"packages": {"packages": {}, "package_count": 5}})
    assert compare_profiles(baseline, target) == []


def test_failed_section_is_not_diffed() -> None:
    baseline = SystemProfile(identity=SystemIdentity(label="baseline"))
    baseline.add_result(
        PluginResult(
            plugin_name="pam", section="pam", status=CollectionStatus.FAILED,
            data={}, errors=["boom"],
        )
    )
    target = _profile("target", {"pam": {"pam_files": {"sshd": ["auth required pam_unix.so"]}}})
    diffs = compare_profiles(baseline, target)
    assert diffs == []


def test_section_missing_on_one_side_reported() -> None:
    baseline = _profile("baseline", {})
    target = _profile("target", {"processes": {"process_signatures": ["root sshd"]}})
    diffs = compare_profiles(baseline, target)
    assert len(diffs) == 1
    assert diffs[0].path == "<section>"
    assert diffs[0].change_type == ChangeType.NEW
