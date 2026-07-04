from __future__ import annotations

from boss_auditor.comparison.engine import RawDifference
from boss_auditor.comparison.intelligence import build_findings, classify_difference
from boss_auditor.comparison.prioritization import compute_priority_score, star_rating_for_score
from boss_auditor.core.models import ChangeType, RiskLevel, StarRating


def test_new_suid_binary_is_critical() -> None:
    diff = RawDifference("suid_sgid", "suid_files[]", ChangeType.NEW, None, "/usr/local/bin/backdoor")
    finding = classify_difference(diff)
    assert finding.risk_score.risk_level == RiskLevel.CRITICAL
    assert finding.privilege_impact is True
    assert "vulnerability" not in finding.title.lower()
    assert "vulnerability" not in finding.description.lower()


def test_new_uid_zero_account_is_critical() -> None:
    diff = RawDifference(
        "users_groups", "users.evil", ChangeType.NEW, None,
        {"uid": "0", "gid": "0", "home": "/root", "shell": "/bin/bash"},
    )
    finding = classify_difference(diff)
    assert finding.risk_score.risk_level == RiskLevel.CRITICAL
    assert finding.risk_score.confidence >= 90


def test_pam_permit_introduction_is_critical() -> None:
    diff = RawDifference("pam", "pam_files.sshd[]", ChangeType.NEW, None, "auth sufficient pam_permit.so")
    finding = classify_difference(diff)
    assert finding.risk_score.risk_level == RiskLevel.CRITICAL
    assert "CWE-287" in finding.cwe_ids


def test_ssh_root_login_enabled_is_critical() -> None:
    diff = RawDifference("ssh_config", "directives.PermitRootLogin", ChangeType.MODIFIED, "no", "yes")
    finding = classify_difference(diff)
    assert finding.risk_score.risk_level == RiskLevel.CRITICAL
    assert finding.attack_surface is True


def test_ssh_hardening_direction_is_low_risk() -> None:
    diff = RawDifference("ssh_config", "directives.PermitRootLogin", ChangeType.MODIFIED, "yes", "no")
    finding = classify_difference(diff)
    assert finding.risk_score.risk_level == RiskLevel.LOW


def test_suspicious_package_flagged_high() -> None:
    diff = RawDifference(
        "packages", "packages.netcat-traditional", ChangeType.NEW, None,
        {"version": "1.10", "status": "install ok installed"},
    )
    finding = classify_difference(diff)
    assert finding.risk_score.risk_level == RiskLevel.HIGH


def test_benign_new_package_is_low_risk() -> None:
    diff = RawDifference(
        "packages", "packages.htop", ChangeType.NEW, None,
        {"version": "3.0", "status": "install ok installed"},
    )
    finding = classify_difference(diff)
    assert finding.risk_score.risk_level == RiskLevel.LOW


def test_process_snapshot_noise_flagged_false_positive() -> None:
    diff = RawDifference("processes", "process_signatures[]", ChangeType.REMOVED, "root cron", None)
    finding = classify_difference(diff)
    assert finding.risk_score.likely_false_positive is True


def test_no_finding_ever_uses_the_word_vulnerability() -> None:
    diffs = [
        RawDifference("suid_sgid", "suid_files[]", ChangeType.NEW, None, "/tmp/x"),
        RawDifference("pam", "pam_files.sshd[]", ChangeType.NEW, None, "auth sufficient pam_permit.so"),
        RawDifference("ssh_config", "directives.PermitRootLogin", ChangeType.MODIFIED, "no", "yes"),
        RawDifference("sysctl", "parameters.kernel.randomize_va_space", ChangeType.MODIFIED, "2", "0"),
        RawDifference("file_permissions", "sensitive_paths./etc/shadow.is_world_writable", ChangeType.MODIFIED, False, True),
    ]
    findings = build_findings(diffs)
    for f in findings:
        blob = " ".join(
            [f.title, f.description, f.why_it_matters, f.possible_impact, f.category]
        ).lower()
        assert "vulnerability" not in blob


def test_findings_sorted_by_priority_descending() -> None:
    diffs = [
        RawDifference("system", "hostname", ChangeType.MODIFIED, "debian", "bossos"),
        RawDifference("suid_sgid", "suid_files[]", ChangeType.NEW, None, "/tmp/x"),
    ]
    findings = build_findings(diffs)
    scores = [f.priority_score for f in findings]
    assert scores == sorted(scores, reverse=True)
    assert findings[0].section == "suid_sgid"


def test_priority_score_and_star_thresholds() -> None:
    score = compute_priority_score(
        risk_level=RiskLevel.CRITICAL, confidence=95, change_type=ChangeType.NEW,
        privilege_impact=True,
    )
    assert star_rating_for_score(score) == StarRating.CRITICAL

    score = compute_priority_score(
        risk_level=RiskLevel.LOW, confidence=40, change_type=ChangeType.MODIFIED,
    )
    assert star_rating_for_score(score) in (StarRating.INFO, StarRating.LOW)


def test_false_positive_dampens_score() -> None:
    base = compute_priority_score(
        risk_level=RiskLevel.HIGH, confidence=80, change_type=ChangeType.NEW,
    )
    dampened = compute_priority_score(
        risk_level=RiskLevel.HIGH, confidence=80, change_type=ChangeType.NEW,
        likely_false_positive=True,
    )
    assert dampened < base
