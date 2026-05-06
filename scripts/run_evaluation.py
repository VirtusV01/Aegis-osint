"""
Evaluation harness: static vs temporal credibility scoring under noise injection.

Sweeps noise levels [0.0, 0.1, 0.2, 0.3, 0.4] × modes [static, temporal] × noise
types [duplicate, misinformation, low_credibility] and records per-combination:

  mean_credibility_genuine  — mean score of ground-truth genuine entities
  mean_credibility_noise    — mean score of injected noise entities
  false_positive_rate       — fraction of noise entities scoring > FP_THRESHOLD
  credibility_gap           — genuine_mean − noise_mean  (higher = better separation)
  graph_edge_count          — total edges in correlation graph (seed + provenance clusters)

Results are written to data/outputs/evaluation_results.json and a summary table
is printed to stdout.  All random operations use GLOBAL_SEED for reproducibility.
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

# Allow running from repo root without pip install
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from osint.services.credibility import compute_credibility
from noise_injection import inject_noise, NoiseType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATASET_PATH = Path("data/samples/synthetic_records.jsonl")
OUTPUT_PATH = Path("data/outputs/evaluation_results.json")
GLOBAL_SEED = 42
FP_THRESHOLD = 0.6
NOISE_LEVELS = [0.0, 0.1, 0.2, 0.3, 0.4]
NOISE_TYPES: List[NoiseType] = ["duplicate", "misinformation", "low_credibility"]
MODES = ["static", "temporal"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_records(path: Path) -> List[Dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


CREDIBILITY_THRESHOLD = 0.40


def _build_graph(
    scored_entities: List[Dict[str, Any]],
    credibility_threshold: float = CREDIBILITY_THRESHOLD,
) -> Tuple[nx.Graph, int]:
    """
    Star topology: seed node + one edge per entity.
    Extra intra-provenance edges: all entities sharing a provenance cluster connect
    to a shared provenance hub node (models corroborative grouping).

    Entities with credibility_score < credibility_threshold are excluded entirely.
    Edges carry a ``weight`` = average credibility of the two connected endpoints
    (seed and hub nodes are treated as having credibility 1.0).

    Returns:
        (G, suppressed_count)
    """
    G = nx.Graph()
    G.add_node("__seed__", kind="seed")
    suppressed_count = 0

    admitted: List[Dict[str, Any]] = []
    for e in scored_entities:
        score = float(e.get("credibility_score") or 0.0)
        if score < credibility_threshold:
            suppressed_count += 1
        else:
            admitted.append(e)

    prov_hubs: Dict[str, str] = {}
    for e in admitted:
        val = str(e.get("value", ""))
        prov = str(e.get("provenance", "unknown"))
        hub = f"__prov__{prov}__"
        score = float(e.get("credibility_score") or 0.0)

        G.add_node(val, kind="entity", etype=e.get("type"))
        # seed has credibility 1.0; weight = (1.0 + entity) / 2
        G.add_edge("__seed__", val, weight=round((1.0 + score) / 2.0, 4))

        if hub not in prov_hubs:
            G.add_node(hub, kind="provenance_hub")
            G.add_edge("__seed__", hub, weight=1.0)
            prov_hubs[hub] = hub
        # hub treated as 1.0
        G.add_edge(hub, val, weight=round((1.0 + score) / 2.0, 4))

    return G, suppressed_count


def _safe_mean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return round(statistics.mean(values), 4)


def _run_single(
    clean_records: List[Dict[str, Any]],
    noise_level: float,
    noise_type: NoiseType,
    mode: str,
) -> Dict[str, Any]:
    """Run one (noise_level, noise_type, mode) cell and return metric dict."""
    noisy, ground_truth = inject_noise(
        clean_records, noise_level, noise_type, seed=GLOBAL_SEED
    )

    genuine_set = set(ground_truth["genuine_ids"])
    noise_set = set(ground_truth["noise_ids"])

    # Score the whole noisy dataset
    scored = compute_credibility(
        [dict(e) for e in noisy],  # avoid mutating the originals
        mode=mode,                 # type: ignore[arg-type]
    )

    genuine_scores: List[float] = []
    noise_scores: List[float] = []

    for e in scored:
        rid = e.get("record_id", "")
        s = e.get("credibility_score", 0.0)
        if rid in genuine_set:
            genuine_scores.append(s)
        elif rid in noise_set:
            noise_scores.append(s)

    mean_genuine = _safe_mean(genuine_scores)
    mean_noise = _safe_mean(noise_scores)

    if noise_scores:
        fp_count = sum(1 for s in noise_scores if s > FP_THRESHOLD)
        fpr = round(fp_count / len(noise_scores), 4)
    else:
        fpr = 0.0

    gap = round(mean_genuine - mean_noise, 4) if (mean_genuine is not None and mean_noise is not None) else None

    G, suppressed = _build_graph(scored)

    return {
        "noise_level": noise_level,
        "noise_type": noise_type,
        "mode": mode,
        "n_total": len(scored),
        "n_genuine": len(genuine_scores),
        "n_noise": len(noise_scores),
        "mean_credibility_genuine": mean_genuine,
        "mean_credibility_noise": mean_noise,
        "false_positive_rate": fpr,
        "credibility_gap": gap,
        "graph_edge_count": G.number_of_edges(),
        "graph_suppressed_count": suppressed,
    }


# ---------------------------------------------------------------------------
# Table printer
# ---------------------------------------------------------------------------

_COL_WIDTHS = [6, 18, 8, 9, 9, 7, 8, 7, 6]
_HEADERS = ["Level", "Noise Type", "Mode", "Mean(G)", "Mean(N)", "FPR", "Gap", "Edges", "Suppr"]


def _row(vals: list) -> str:
    return "  ".join(str(v).ljust(w) for v, w in zip(vals, _COL_WIDTHS))


def _fmt(v: Any) -> str:
    if v is None:
        return "N/A"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def print_table(results: List[Dict[str, Any]]) -> None:
    sep = "-" * 88
    print(sep)
    print(_row(_HEADERS))
    print(sep)
    for r in results:
        print(_row([
            f"{r['noise_level']:.2f}",
            r["noise_type"],
            r["mode"],
            _fmt(r["mean_credibility_genuine"]),
            _fmt(r["mean_credibility_noise"]),
            _fmt(r["false_positive_rate"]),
            _fmt(r["credibility_gap"]),
            r["graph_edge_count"],
            r.get("graph_suppressed_count", "N/A"),
        ]))
    print(sep)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    if not DATASET_PATH.exists():
        print(f"Dataset not found at {DATASET_PATH}. Run generate_synthetic_dataset.py first.")
        sys.exit(1)

    clean = _load_records(DATASET_PATH)
    print(f"Loaded {len(clean)} clean entity records from {DATASET_PATH}\n")

    results: List[Dict[str, Any]] = []

    total_cells = len(NOISE_LEVELS) * len(NOISE_TYPES) * len(MODES)
    done = 0

    for noise_level in NOISE_LEVELS:
        for noise_type in NOISE_TYPES:
            for mode in MODES:
                cell = _run_single(clean, noise_level, noise_type, mode)
                results.append(cell)
                done += 1
                print(f"  [{done:>2}/{total_cells}]  level={noise_level:.1f}  "
                      f"type={noise_type:<18}  mode={mode:<8}  "
                      f"gap={_fmt(cell['credibility_gap'])}")

    print()
    print_table(results)

    # Summary statistics per mode across all noise levels and types
    print("\nSummary: mean credibility_gap by mode")
    for mode in MODES:
        gaps = [r["credibility_gap"] for r in results if r["mode"] == mode and r["credibility_gap"] is not None]
        print(f"  {mode:<8}  mean_gap={_safe_mean(gaps)}")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": {
            "seed": GLOBAL_SEED,
            "fp_threshold": FP_THRESHOLD,
            "noise_levels": NOISE_LEVELS,
            "noise_types": NOISE_TYPES,
            "modes": MODES,
            "n_clean_records": len(clean),
        },
        "results": results,
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nFull results -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
