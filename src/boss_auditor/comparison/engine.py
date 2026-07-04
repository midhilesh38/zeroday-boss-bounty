"""Phase 3 — Differential Engine.

Loads two `SystemProfile` snapshots (baseline + target) and produces a flat
list of `RawDifference` records describing every field-level change
between them. This module knows nothing about risk or priority -- it is
pure, deterministic evidence extraction. Phase 4 (`comparison.intelligence`)
is what turns these into `Finding` objects.

Diff strategy, chosen to match the actual shapes collector plugins
produce (see `plugins/collectors/*.py`):

  * dict of key -> scalar/dict  (e.g. packages, sysctl params, users,
    sshd directives): key-level diff. A key only in baseline is
    "removed"; only in target is "new"; present in both with a different
    value is "modified" (recursing into nested dicts).
  * list of str (e.g. suid_files, apt_repositories, process_signatures):
    treated as a set. Items only in target are "new"; only in baseline
    are "removed". Order and duplicates are not meaningful for these
    sections, so this avoids reporting noise from re-ordering.
  * scalar vs scalar: direct equality check -> "modified" if different.

A small set of derived/metadata keys (e.g. `package_count`,
`parameter_count`) are excluded because they're redundant with the
per-item diff and would otherwise show up as noisy near-duplicate
findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from boss_auditor.core.models import ChangeType, SystemProfile

_MISSING = object()

# Derived/summary fields that duplicate information already captured by
# per-item diffing elsewhere in the same section.
_EXCLUDED_KEYS: frozenset[str] = frozenset(
    {"package_count", "parameter_count", "pam_file_count"}
)


@dataclass(frozen=True, slots=True)
class RawDifference:
    section: str
    path: str
    change_type: ChangeType
    baseline_value: Any
    target_value: Any


def _diff_value(
    section: str, path: str, b_val: Any, t_val: Any
) -> list[RawDifference]:
    if b_val is _MISSING:
        return [RawDifference(section, path, ChangeType.NEW, None, t_val)]
    if t_val is _MISSING:
        return [RawDifference(section, path, ChangeType.REMOVED, b_val, None)]

    if b_val == t_val:
        return []

    if isinstance(b_val, dict) and isinstance(t_val, dict):
        results: list[RawDifference] = []
        for key in sorted(set(b_val) | set(t_val)):
            if key in _EXCLUDED_KEYS:
                continue
            results.extend(
                _diff_value(section, f"{path}.{key}", b_val.get(key, _MISSING), t_val.get(key, _MISSING))
            )
        return results

    if isinstance(b_val, list) and isinstance(t_val, list):
        # Sets of hashable items (strings) is the only shape our
        # collectors produce for list fields. If a list contains
        # unhashable items (shouldn't happen given current collectors),
        # fall back to a direct scalar-style comparison.
        try:
            b_set, t_set = set(b_val), set(t_val)
        except TypeError:
            return [RawDifference(section, path, ChangeType.MODIFIED, b_val, t_val)]

        results = []
        for item in sorted(t_set - b_set):
            results.append(RawDifference(section, f"{path}[]", ChangeType.NEW, None, item))
        for item in sorted(b_set - t_set):
            results.append(RawDifference(section, f"{path}[]", ChangeType.REMOVED, item, None))
        return results

    # Scalar mismatch (or type mismatch between the two sides, which is
    # itself worth surfacing as a modification).
    return [RawDifference(section, path, ChangeType.MODIFIED, b_val, t_val)]


def diff_section(section: str, baseline_data: dict, target_data: dict) -> list[RawDifference]:
    results: list[RawDifference] = []
    for key in sorted(set(baseline_data) | set(target_data)):
        if key in _EXCLUDED_KEYS:
            continue
        results.extend(
            _diff_value(section, key, baseline_data.get(key, _MISSING), target_data.get(key, _MISSING))
        )
    return results


def compare_profiles(baseline: SystemProfile, target: SystemProfile) -> list[RawDifference]:
    """Compare every section present in either profile. A section present
    in only one profile (e.g. a collector that failed on one host) is
    reported as a single section-level difference rather than silently
    skipped, so the researcher knows collection coverage differed."""
    all_sections = set(baseline.sections) | set(target.sections)
    differences: list[RawDifference] = []

    for section in sorted(all_sections):
        b_result = baseline.sections.get(section)
        t_result = target.sections.get(section)

        if b_result is None:
            differences.append(
                RawDifference(section, "<section>", ChangeType.NEW, None, "section only present on target")
            )
            continue
        if t_result is None:
            differences.append(
                RawDifference(section, "<section>", ChangeType.REMOVED, "section only present on baseline", None)
            )
            continue
        if b_result.status != "ok" or t_result.status != "ok":
            # Don't attempt to diff data from a section that failed to
            # collect on either side -- that would produce misleading
            # "removed everything" noise.
            continue

        differences.extend(diff_section(section, b_result.data, t_result.data))

    return differences
