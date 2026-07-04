"""Persist and load `SystemProfile` snapshots as structured JSON.

This is the Phase 1 deliverable: baseline and target scans are stored as
JSON files under the configured profile directory, ready for the Phase 3
differential engine to consume.
"""

from __future__ import annotations

from pathlib import Path

from boss_auditor.core.exceptions import ProfileError
from boss_auditor.core.models import SystemProfile


def save_profile(profile: SystemProfile, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_profile(path: Path | str) -> SystemProfile:
    path = Path(path)
    if not path.exists():
        raise ProfileError(f"Profile not found: {path}")
    try:
        return SystemProfile.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pydantic.ValidationError, kept generic here
        raise ProfileError(f"Could not load profile at {path}: {exc}") from exc
