from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Literal, Tuple

from osint.services.temporal_decay import compute_decay_breakdown


# Tuneable reputation weights per provenance/module
SOURCE_REPUTATION: Dict[str, float] = {
    "sfp_shodan": 0.85,
    "whois_synth": 0.70,
    "records_synth": 0.60,
    "unknown": 0.50,
    "correlate": 0.55,
}


def _key(e: Dict[str, Any]) -> Tuple[str, str]:
    return (str(e.get("type", "")), str(e.get("value", "")))


def compute_credibility(
    entities: List[Dict[str, Any]],
    *,
    mode: Literal["temporal", "static"] = "temporal",
    half_life_days: float = 30.0,
) -> List[Dict[str, Any]]:
    """
    Explainable credibility scoring with optional temporal decay.

    Static mode (original formula, for comparison baselines in experiments):
        credibility = 0.6 * corroboration + 0.4 * source_reputation

    Temporal mode (decay-aware, primary model):
        credibility = 0.5 * corroboration + 0.3 * source_reputation + 0.2 * decay

    Where:
        corroboration   = min(1.0, distinct_source_count / 3)
        source_reputation = SOURCE_REPUTATION[provenance]  (default 0.5)
        decay           = compute_decay_factor(entity['last_seen'])

    Full breakdown stored under meta['credibility_breakdown'] including the
    decay factor, age_days, half_life_days, and the mode used.  This makes
    every score fully auditable for the research paper's reproducibility claims.

    Args:
        entities:       List of entity dicts (mutated in-place; also returned).
        mode:           "temporal" (default) or "static" (reproduces original formula).
        half_life_days: Half-life for the exponential decay model (temporal mode only).

    Returns:
        The same list with 'credibility_score' and 'meta.credibility_breakdown' set.
    """
    # Build cross-entity corroboration map (distinct provenances per identity key)
    sources_by_entity: Dict[Tuple[str, str], set] = defaultdict(set)
    for e in entities:
        sources_by_entity[_key(e)].add(str(e.get("provenance", "unknown")))

    for e in entities:
        prov = str(e.get("provenance", "unknown"))
        rep = float(SOURCE_REPUTATION.get(prov, SOURCE_REPUTATION["unknown"]))

        src_count = len(sources_by_entity[_key(e)])
        corroboration = min(1.0, src_count / 3.0)  # >=3 distinct sources => 1.0

        meta = e.get("meta") or {}

        if mode == "static":
            final = round(0.6 * corroboration + 0.4 * rep, 3)
            meta["credibility_breakdown"] = {
                "corroboration": round(corroboration, 3),
                "source_reputation": round(rep, 3),
                "sources_seen": sorted(sources_by_entity[_key(e)]),
                "formula": "0.6*corroboration + 0.4*source_reputation",
                "mode": "static",
            }

        else:  # temporal
            decay_bd = compute_decay_breakdown(
                e.get("last_seen"),
                half_life_days=half_life_days,
            )
            decay = decay_bd["decay_factor"]
            final = round(0.5 * corroboration + 0.3 * rep + 0.2 * decay, 3)
            meta["credibility_breakdown"] = {
                "corroboration": round(corroboration, 3),
                "source_reputation": round(rep, 3),
                "decay_factor": decay,
                "age_days": decay_bd.get("age_days"),
                "half_life_days": half_life_days,
                "sources_seen": sorted(sources_by_entity[_key(e)]),
                "formula": "0.5*corroboration + 0.3*source_reputation + 0.2*decay",
                "mode": "temporal",
            }

        e["credibility_score"] = final
        e["meta"] = meta

    return entities