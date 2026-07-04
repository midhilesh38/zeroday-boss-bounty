"""Phase 5 — Smart Prioritization.

A `Finding`'s star rating is never just its risk level -- it also factors
in whether the difference touches a privilege boundary, expands network
attack surface, grants persistence, and how much it deviates from a clean
Debian default (new/removed things deviate more than a value tweak).

The formula is intentionally simple and fully deterministic/offline so a
researcher (or a competition judge) can audit exactly why something ranked
where it did -- no ML, no black box.
"""

from __future__ import annotations

from boss_auditor.core.models import ChangeType, RiskLevel, StarRating

_RISK_WEIGHTS: dict[RiskLevel, float] = {
    RiskLevel.CRITICAL: 100.0,
    RiskLevel.HIGH: 75.0,
    RiskLevel.MEDIUM: 50.0,
    RiskLevel.LOW: 25.0,
}

_DEVIATION_WEIGHT_NEW_REMOVED = 8.0
_DEVIATION_WEIGHT_MODIFIED = 0.0

_PRIVILEGE_IMPACT_BONUS = 15.0
_ATTACK_SURFACE_BONUS = 10.0
_PERSISTENCE_BONUS = 10.0

_FALSE_POSITIVE_DAMPING = 0.4


def compute_priority_score(
    *,
    risk_level: RiskLevel,
    confidence: int,
    change_type: ChangeType,
    privilege_impact: bool = False,
    attack_surface: bool = False,
    persistence: bool = False,
    likely_false_positive: bool = False,
) -> float:
    """Combine risk, confidence, and Phase-5 structural signals into one
    orderable score. Higher = investigate sooner."""
    score = _RISK_WEIGHTS[risk_level] * (confidence / 100.0)

    if change_type in (ChangeType.NEW, ChangeType.REMOVED):
        score += _DEVIATION_WEIGHT_NEW_REMOVED
    else:
        score += _DEVIATION_WEIGHT_MODIFIED

    if privilege_impact:
        score += _PRIVILEGE_IMPACT_BONUS
    if attack_surface:
        score += _ATTACK_SURFACE_BONUS
    if persistence:
        score += _PERSISTENCE_BONUS

    if likely_false_positive:
        # A likely-false-positive candidate is dampened rather than
        # dropped -- the researcher still sees it, just not at the top.
        score *= _FALSE_POSITIVE_DAMPING

    return round(score, 2)


def star_rating_for_score(score: float) -> StarRating:
    if score >= 90:
        return StarRating.CRITICAL
    if score >= 65:
        return StarRating.HIGH
    if score >= 40:
        return StarRating.MEDIUM
    if score >= 20:
        return StarRating.LOW
    return StarRating.INFO
