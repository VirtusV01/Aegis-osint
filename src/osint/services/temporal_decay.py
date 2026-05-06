"""
Temporal credibility decay for OSINT entities.

Model: exponential half-life decay
    decay(t) = e^(-λt),  λ = ln(2) / half_life_days

At t=0 (brand new):          decay = 1.0   (full trust)
At t=half_life_days (30 d):  decay ≈ 0.5   (half trust)
At t=2*half_life_days (60d): decay ≈ 0.25  (quarter trust)
"""
from __future__ import annotations

import math
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

# Default tuning constant — override per call when running ablation experiments.
HALF_LIFE_DAYS: float = 30.0

# Pre-computed λ for the default half-life (avoids recomputing in tight loops).
_DEFAULT_LAMBDA: float = math.log(2) / HALF_LIFE_DAYS


def compute_decay_factor(
    last_seen_iso: Optional[str],
    *,
    half_life_days: float = HALF_LIFE_DAYS,
) -> float:
    """
    Return a decay weight in [0.0, 1.0] based on entity age.

    Args:
        last_seen_iso: ISO-8601 timestamp string of the entity's last observation.
                       Pass None to signal a newly discovered entity (no penalty).
        half_life_days: Days after which the weight halves.  Default 30.

    Returns:
        1.0  — if last_seen_iso is None (new entity, no temporal penalty).
        float in (0, 1] — exponential decay weight based on elapsed days.
    """
    if last_seen_iso is None:
        return 1.0
    return _decay_breakdown(last_seen_iso, half_life_days)["decay_factor"]


def compute_decay_breakdown(
    last_seen_iso: Optional[str],
    *,
    half_life_days: float = HALF_LIFE_DAYS,
) -> Dict[str, Any]:
    """
    Return a fully explainable breakdown dict for use in credibility metadata.

    Keys always present:
        decay_factor   — float in (0, 1], the weight applied to the score
        age_days       — float | None, elapsed days since last_seen
        half_life_days — the half-life parameter used
        lambda         — decay rate λ = ln(2) / half_life_days
        formula        — human-readable formula string
    """
    if last_seen_iso is None:
        return {
            "decay_factor": 1.0,
            "age_days": None,
            "half_life_days": half_life_days,
            "lambda": round(math.log(2) / half_life_days, 6),
            "formula": "e^(-λ*t)",
            "note": "last_seen is None — no temporal penalty applied",
        }
    return _decay_breakdown(last_seen_iso, half_life_days)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_iso(ts: str) -> datetime:
    """Parse ISO-8601 string; attach UTC if tz-naive."""
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _decay_breakdown(last_seen_iso: str, half_life_days: float) -> Dict[str, Any]:
    lam = math.log(2) / half_life_days
    now = datetime.now(timezone.utc)
    last_seen_dt = _parse_iso(last_seen_iso)
    age_seconds = max(0.0, (now - last_seen_dt).total_seconds())
    age_days = age_seconds / 86400.0
    decay = math.exp(-lam * age_days)
    return {
        "decay_factor": round(decay, 6),
        "age_days": round(age_days, 3),
        "half_life_days": half_life_days,
        "lambda": round(lam, 6),
        "formula": "e^(-λ*t)",
    }