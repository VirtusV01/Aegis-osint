"""
Tests for temporal credibility decay model.

Covers:
  - decay factor boundary values (None, brand-new, 30d, 60d, 3d)
  - compute_decay_breakdown structure
  - credibility static mode reproduces the original formula exactly
  - credibility temporal mode scores old entities lower than new ones
"""
from __future__ import annotations

import math
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import pytest

from osint.services.temporal_decay import compute_decay_factor, compute_decay_breakdown
from osint.services.credibility import compute_credibility, SOURCE_REPUTATION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_ago(days: float) -> str:
    """Return an ISO-8601 UTC timestamp `days` days in the past."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _entity(
    value: str = "1.2.3.4",
    prov: str = "sfp_shodan",
    last_seen: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "type": "ip",
        "value": value,
        "provenance": prov,
        "last_seen": last_seen,
        "meta": {},
    }


# ---------------------------------------------------------------------------
# compute_decay_factor tests
# ---------------------------------------------------------------------------

class TestDecayFactor:
    def test_none_last_seen_returns_one(self):
        """No last_seen means a brand-new entity — no temporal penalty."""
        assert compute_decay_factor(None) == 1.0

    def test_brand_new_entity_near_one(self):
        """Entity seen moments ago should have a decay factor very close to 1.0."""
        factor = compute_decay_factor(_iso_ago(0))
        assert factor > 0.999, f"Expected >0.999 for entity seen 0 days ago, got {factor}"

    def test_3_days_old_above_0_9(self):
        """An entity 3 days old retains more than 90 % of its temporal credibility."""
        factor = compute_decay_factor(_iso_ago(3))
        expected_floor = math.exp(-math.log(2) / 30.0 * 3)  # ≈ 0.933
        assert factor > 0.9, f"Expected >0.9 for 3-day-old entity, got {factor}"
        assert abs(factor - expected_floor) < 0.005

    def test_half_life_30_days(self):
        """At exactly one half-life (30 days), decay factor must be ≈ 0.5."""
        factor = compute_decay_factor(_iso_ago(30))
        assert abs(factor - 0.5) < 0.01, f"Expected ≈0.5 at 30 days, got {factor}"

    def test_double_half_life_60_days(self):
        """At two half-lives (60 days), decay factor must be ≈ 0.25."""
        factor = compute_decay_factor(_iso_ago(60))
        assert abs(factor - 0.25) < 0.01, f"Expected ≈0.25 at 60 days, got {factor}"

    def test_custom_half_life(self):
        """Custom half_life_days is honoured: at t=half_life factor ≈ 0.5."""
        factor = compute_decay_factor(_iso_ago(7), half_life_days=7.0)
        assert abs(factor - 0.5) < 0.01, f"Expected ≈0.5 with 7-day half-life at 7 days, got {factor}"

    def test_factor_is_bounded(self):
        """Decay factor must always be in (0, 1]."""
        for days in [0, 1, 7, 30, 90, 365]:
            f = compute_decay_factor(_iso_ago(days))
            assert 0.0 < f <= 1.0, f"factor out of bounds at {days} days: {f}"

    def test_older_entity_lower_factor(self):
        """Monotonicity: older entities must always score lower."""
        factors = [compute_decay_factor(_iso_ago(d)) for d in [0, 7, 30, 60, 120]]
        for i in range(len(factors) - 1):
            assert factors[i] >= factors[i + 1], "Decay is not monotonically decreasing"


# ---------------------------------------------------------------------------
# compute_decay_breakdown tests
# ---------------------------------------------------------------------------

class TestDecayBreakdown:
    def test_none_breakdown_structure(self):
        bd = compute_decay_breakdown(None)
        assert bd["decay_factor"] == 1.0
        assert bd["age_days"] is None
        assert "half_life_days" in bd
        assert "lambda" in bd
        assert "formula" in bd
        assert "note" in bd

    def test_breakdown_fields_present(self):
        bd = compute_decay_breakdown(_iso_ago(30))
        required = {"decay_factor", "age_days", "half_life_days", "lambda", "formula"}
        assert required.issubset(bd.keys()), f"Missing keys: {required - bd.keys()}"

    def test_breakdown_age_days_matches_input(self):
        bd = compute_decay_breakdown(_iso_ago(45))
        assert abs(bd["age_days"] - 45.0) < 0.1, (
            f"Expected age_days ≈ 45, got {bd['age_days']}"
        )

    def test_breakdown_lambda_matches_formula(self):
        bd = compute_decay_breakdown(_iso_ago(10), half_life_days=14.0)
        expected_lam = math.log(2) / 14.0
        assert abs(bd["lambda"] - expected_lam) < 1e-5

    def test_breakdown_decay_factor_consistent(self):
        """decay_factor in breakdown must agree with compute_decay_factor."""
        ts = _iso_ago(30)
        factor = compute_decay_factor(ts)
        bd = compute_decay_breakdown(ts)
        assert abs(factor - bd["decay_factor"]) < 1e-6


# ---------------------------------------------------------------------------
# compute_credibility static mode tests
# ---------------------------------------------------------------------------

class TestCredibilityStaticMode:
    def test_static_matches_original_formula_single_source(self):
        """
        Static mode must exactly reproduce: 0.6*corroboration + 0.4*source_reputation.
        With 1 source: corroboration = 1/3.
        """
        e = _entity(prov="sfp_shodan", last_seen=_iso_ago(90))
        result = compute_credibility([e], mode="static")
        rep = SOURCE_REPUTATION["sfp_shodan"]  # 0.85
        corr = 1 / 3.0
        expected = round(0.6 * corr + 0.4 * rep, 3)
        assert result[0]["credibility_score"] == expected

    def test_static_matches_original_formula_three_sources(self):
        """With 3 distinct provenances, corroboration reaches 1.0."""
        entities = [
            _entity(value="9.9.9.9", prov="sfp_shodan"),
            _entity(value="9.9.9.9", prov="whois_synth"),
            _entity(value="9.9.9.9", prov="records_synth"),
        ]
        result = compute_credibility(entities, mode="static")
        # All three entities share the same (type, value) so corroboration = 1.0
        scores = {r["credibility_score"] for r in result}
        rep_shodan = SOURCE_REPUTATION["sfp_shodan"]
        expected_shodan = round(0.6 * 1.0 + 0.4 * rep_shodan, 3)
        assert expected_shodan in scores

    def test_static_breakdown_formula_label(self):
        e = _entity()
        result = compute_credibility([e], mode="static")
        bd = result[0]["meta"]["credibility_breakdown"]
        assert bd["formula"] == "0.6*corroboration + 0.4*source_reputation"
        assert bd["mode"] == "static"
        assert "decay_factor" not in bd  # static must not expose decay

    def test_static_ignores_last_seen(self):
        """Static mode must produce identical scores regardless of last_seen."""
        old = _entity(value="8.8.8.8", last_seen=_iso_ago(365))
        fresh = _entity(value="8.8.8.9", last_seen=_iso_ago(0))
        result = compute_credibility([old, fresh], mode="static")
        assert result[0]["credibility_score"] == result[1]["credibility_score"]


# ---------------------------------------------------------------------------
# compute_credibility temporal mode tests
# ---------------------------------------------------------------------------

class TestCredibilityTemporalMode:
    def test_temporal_lower_score_for_old_entity(self):
        """
        Core research claim: temporal mode must give old entities lower scores.
        Uses two distinct entity values to avoid cross-corroboration.
        """
        old = _entity(value="10.0.0.1", prov="sfp_shodan", last_seen=_iso_ago(90))
        new_e = _entity(value="10.0.0.2", prov="sfp_shodan", last_seen=_iso_ago(0))
        results = compute_credibility([old, new_e], mode="temporal")
        old_score = next(r["credibility_score"] for r in results if r["value"] == "10.0.0.1")
        new_score = next(r["credibility_score"] for r in results if r["value"] == "10.0.0.2")
        assert old_score < new_score, (
            f"Old entity ({old_score}) should score lower than new entity ({new_score})"
        )

    def test_temporal_none_last_seen_no_penalty(self):
        """
        Entity with last_seen=None must receive the same decay weight as
        an entity seen moments ago (both get decay=1.0).
        """
        e_none = _entity(value="5.5.5.5", last_seen=None)
        e_now = _entity(value="6.6.6.6", last_seen=_iso_ago(0))
        results = compute_credibility([e_none, e_now], mode="temporal")
        score_none = next(r["credibility_score"] for r in results if r["value"] == "5.5.5.5")
        score_now = next(r["credibility_score"] for r in results if r["value"] == "6.6.6.6")
        assert abs(score_none - score_now) < 0.01, (
            f"None and brand-new should score almost identically: {score_none} vs {score_now}"
        )

    def test_temporal_breakdown_has_required_keys(self):
        e = _entity(last_seen=_iso_ago(30))
        result = compute_credibility([e], mode="temporal")
        bd = result[0]["meta"]["credibility_breakdown"]
        required = {
            "corroboration", "source_reputation", "decay_factor",
            "age_days", "half_life_days", "sources_seen", "formula", "mode",
        }
        assert required.issubset(bd.keys()), f"Missing breakdown keys: {required - bd.keys()}"

    def test_temporal_breakdown_formula_label(self):
        e = _entity(last_seen=_iso_ago(15))
        result = compute_credibility([e], mode="temporal")
        bd = result[0]["meta"]["credibility_breakdown"]
        assert bd["formula"] == "0.5*corroboration + 0.3*source_reputation + 0.2*decay"
        assert bd["mode"] == "temporal"

    def test_temporal_half_life_score(self):
        """
        At exactly the default half-life (30 days), decay=0.5.
        Validate the full score arithmetic for a single-source sfp_shodan entity.
        """
        e = _entity(prov="sfp_shodan", last_seen=_iso_ago(30))
        result = compute_credibility([e], mode="temporal")
        bd = result[0]["meta"]["credibility_breakdown"]
        rep = SOURCE_REPUTATION["sfp_shodan"]  # 0.85
        corr = 1 / 3.0
        decay = bd["decay_factor"]
        expected = round(0.5 * corr + 0.3 * rep + 0.2 * decay, 3)
        assert result[0]["credibility_score"] == expected

    def test_temporal_custom_half_life_honoured(self):
        """half_life_days parameter must be reflected in the breakdown."""
        e = _entity(last_seen=_iso_ago(7))
        result = compute_credibility([e], mode="temporal", half_life_days=7.0)
        bd = result[0]["meta"]["credibility_breakdown"]
        assert bd["half_life_days"] == 7.0
        assert abs(bd["decay_factor"] - 0.5) < 0.01