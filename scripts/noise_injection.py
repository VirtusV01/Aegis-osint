"""
Controlled noise injection for OSINT credibility evaluation experiments.

Three noise types mimic real-world data quality failures:
  DUPLICATE      — near-duplicate records with minor value mutations (data ingestion artefacts)
  MISINFORMATION — plausible-but-wrong entity values (adversarial spoofing / data poisoning)
  LOW_CREDIBILITY — records from unknown provenance with generic content (forum scrapes, etc.)

All random operations accept a seed for full reproducibility.
"""
from __future__ import annotations

import copy
import json
import random
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Literal, Tuple

NoiseType = Literal["duplicate", "misinformation", "low_credibility", "all"]

# ---------------------------------------------------------------------------
# Value mutators — each returns a plausible but distinct string
# ---------------------------------------------------------------------------

_TLD_SWAPS = {
    ".com": [".net", ".org", ".io", ".co"],
    ".net": [".com", ".org", ".io"],
    ".org": [".com", ".net", ".info"],
    ".io":  [".com", ".co", ".ai"],
    ".ru":  [".com", ".net", ".su"],
    ".tk":  [".ml", ".ga", ".cf"],
    ".xyz": [".top", ".club", ".site"],
    ".ai":  [".io", ".com"],
    ".cc":  [".com", ".net"],
}


def _mutate_duplicate(value: str, entity_type: str, rng: random.Random) -> str:
    """Minor variation — still looks like the same entity at a glance."""
    if entity_type == "ip":
        parts = value.split(".")
        if len(parts) == 4:
            try:
                last = int(parts[-1])
                parts[-1] = str(min(254, last + rng.choice([-1, 1])))
                return ".".join(parts)
            except ValueError:
                pass
    if entity_type == "domain":
        # add/remove trailing hyphen segment or prefix 'www.'
        if value.startswith("www."):
            return value[4:]
        return "www." + value
    if entity_type == "email":
        user, _, domain = value.partition("@")
        return f"{user}_{rng.randint(1, 9)}@{domain}"
    if entity_type == "person":
        parts = value.split()
        if len(parts) >= 2:
            return " ".join(reversed(parts))  # swap first/last name
    # fallback: append a digit
    return value + str(rng.randint(1, 9))


def _mutate_misinformation(value: str, entity_type: str, rng: random.Random) -> str:
    """Plausible-but-wrong value — convincingly wrong, not obviously garbage."""
    if entity_type == "ip":
        parts = value.split(".")
        if len(parts) == 4:
            try:
                idx = rng.randint(0, 2)  # alter one of first three octets
                parts[idx] = str(rng.randint(1, 254))
                return ".".join(parts)
            except ValueError:
                pass
    if entity_type == "domain":
        for old_tld, replacements in _TLD_SWAPS.items():
            if value.endswith(old_tld):
                return value[: -len(old_tld)] + rng.choice(replacements)
        # no known TLD — just swap a character in the SLD
        base = value.split(".")[0]
        if len(base) > 2:
            pos = rng.randint(1, len(base) - 1)
            char = rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
            mutated_base = base[:pos] + char + base[pos + 1:]
            return value.replace(base, mutated_base, 1)
    if entity_type == "email":
        user, _, domain = value.partition("@")
        # mangle username: replace vowels with digits
        vowels = re.sub(r"[^aeiou]", "", user)
        if vowels:
            v = rng.choice(vowels)
            user = user.replace(v, str(rng.randint(0, 9)), 1)
        return f"{user}@{domain}"
    if entity_type == "person":
        # swap first name with a different one from a small pool
        fakes = ["James", "Maria", "Chen", "Olga", "Kwame", "Sara"]
        parts = value.split()
        if parts:
            parts[0] = rng.choice(fakes)
        return " ".join(parts)
    if entity_type in ("org", "registrar"):
        suffixes = ["Ltd", "GmbH", "Corp", "LLC", "Inc", "SA"]
        base = re.sub(r"\b(Ltd|GmbH|Corp|LLC|Inc|SA)\b", "", value).strip()
        return f"{base} {rng.choice(suffixes)}"
    return value[::-1]  # last resort: reverse


_LOW_CRED_VALUES = {
    "ip":     ["0.0.0.0", "127.0.0.1", "255.255.255.255", "10.0.0.1", "172.16.0.1"],
    "domain": ["unknown-host.local", "generic-site.com", "placeholder.net", "filler.org"],
    "email":  ["user@unknown.com", "nobody@generic.net", "anon@placeholder.org"],
    "person": ["Unknown Person", "Anonymous", "N/A User"],
    "org":    ["Unknown Organization", "Generic Corp", "Unnamed Entity"],
}

_ALL_TYPES = list(_LOW_CRED_VALUES.keys())


def _low_cred_entity(counter: int, rng: random.Random) -> Dict[str, Any]:
    etype = rng.choice(_ALL_TYPES)
    return {
        "record_id": f"noise_{counter:05d}",
        "type": etype,
        "value": rng.choice(_LOW_CRED_VALUES[etype]),
        "provenance": "unknown",
        "last_seen": (
            datetime.now(timezone.utc) - timedelta(days=rng.uniform(0, 14))
        ).isoformat(),
        "meta": {"injected": True, "noise_type": "low_credibility"},
    }


# ---------------------------------------------------------------------------
# Core injection function
# ---------------------------------------------------------------------------

def inject_noise(
    records: List[Dict[str, Any]],
    noise_level: float,
    noise_type: NoiseType,
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Inject noise into a clean entity record list.

    Args:
        records:      Clean entity records (must each have a 'record_id').
        noise_level:  Fraction of clean dataset size to inject (0.0 – 1.0).
                      E.g. 0.1 = 10% of len(records) noise records.
        noise_type:   Which injection strategy to apply.
                      "all" applies all three in equal thirds.
        seed:         RNG seed for full reproducibility.

    Returns:
        (noisy_records, ground_truth) where ground_truth is a dict with keys:
            genuine_ids  — record_ids of unmodified clean records
            noise_ids    — record_ids of injected/replaced records
            noise_type   — the strategy used
            noise_level  — the parameter used
            n_genuine    — count of genuine records
            n_noise      — count of noise records
    """
    if not 0.0 <= noise_level <= 1.0:
        raise ValueError(f"noise_level must be in [0, 1], got {noise_level}")

    rng = random.Random(seed)
    n_noise = round(len(records) * noise_level)

    genuine_ids: List[str] = [r["record_id"] for r in records]
    noise_ids: List[str] = []

    if n_noise == 0 or noise_type not in ("duplicate", "misinformation", "low_credibility", "all"):
        if n_noise == 0:
            return (
                copy.deepcopy(records),
                {
                    "genuine_ids": genuine_ids,
                    "noise_ids": [],
                    "noise_type": noise_type,
                    "noise_level": noise_level,
                    "n_genuine": len(genuine_ids),
                    "n_noise": 0,
                },
            )

    result = copy.deepcopy(records)
    noise_counter = [0]

    def _next_noise_id() -> str:
        nid = f"noise_{noise_counter[0]:05d}"
        noise_counter[0] += 1
        return nid

    # Decide per-type budgets
    if noise_type == "all":
        budgets = {
            "duplicate": n_noise // 3,
            "misinformation": n_noise // 3,
            "low_credibility": n_noise - 2 * (n_noise // 3),
        }
    else:
        budgets = {noise_type: n_noise}

    # ------------------------------------------------------------------ #
    # DUPLICATE: append near-copies; genuine records stay untouched
    # ------------------------------------------------------------------ #
    if budgets.get("duplicate", 0) > 0:
        k = budgets["duplicate"]
        sources = rng.choices(result, k=k)
        for src in sources:
            clone = copy.deepcopy(src)
            clone["record_id"] = _next_noise_id()
            clone["value"] = _mutate_duplicate(src["value"], src["type"], rng)
            clone.setdefault("meta", {})["injected"] = True
            clone["meta"]["noise_type"] = "duplicate"
            noise_ids.append(clone["record_id"])
            result.append(clone)

    # ------------------------------------------------------------------ #
    # MISINFORMATION: replace N records in-place; originals become noise
    # ------------------------------------------------------------------ #
    if budgets.get("misinformation", 0) > 0:
        k = budgets["misinformation"]
        idxs = rng.sample(range(len(records)), min(k, len(records)))
        for idx in idxs:
            rec = result[idx]
            original_id = rec["record_id"]
            new_id = _next_noise_id()
            # mark original as noise (it carries wrong value now)
            if original_id in genuine_ids:
                genuine_ids.remove(original_id)
            rec["record_id"] = new_id
            rec["value"] = _mutate_misinformation(rec["value"], rec["type"], rng)
            rec.setdefault("meta", {})["injected"] = True
            rec["meta"]["noise_type"] = "misinformation"
            noise_ids.append(new_id)

    # ------------------------------------------------------------------ #
    # LOW_CREDIBILITY: append brand-new low-signal records
    # ------------------------------------------------------------------ #
    if budgets.get("low_credibility", 0) > 0:
        for _ in range(budgets["low_credibility"]):
            lc = _low_cred_entity(noise_counter[0], rng)
            noise_counter[0] += 1
            noise_ids.append(lc["record_id"])
            result.append(lc)

    # Shuffle so noise isn't always at the tail (prevents look-ahead bias)
    rng.shuffle(result)

    ground_truth = {
        "genuine_ids": genuine_ids,
        "noise_ids": noise_ids,
        "noise_type": noise_type,
        "noise_level": noise_level,
        "n_genuine": len(genuine_ids),
        "n_noise": len(noise_ids),
    }
    return result, ground_truth


# ---------------------------------------------------------------------------
# CLI convenience
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Inject noise into a JSONL entity dataset")
    parser.add_argument("input", help="Clean JSONL dataset path")
    parser.add_argument("output", help="Output JSONL path for noisy dataset")
    parser.add_argument("--level", type=float, default=0.1)
    parser.add_argument("--type", dest="noise_type", default="all",
                        choices=["duplicate", "misinformation", "low_credibility", "all"])
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    records = [json.loads(l) for l in Path(args.input).read_text(encoding="utf-8").splitlines() if l.strip()]
    noisy, gt = inject_noise(records, args.level, args.noise_type, args.seed)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for r in noisy:
            f.write(json.dumps(r) + "\n")

    gt_path = out.with_suffix("").parent / f"{out.stem}_ground_truth.json"
    gt_path.write_text(json.dumps(gt, indent=2), encoding="utf-8")
    print(f"Wrote {len(noisy)} records → {out}")
    print(f"Ground truth → {gt_path}  (genuine={gt['n_genuine']}, noise={gt['n_noise']})")


if __name__ == "__main__":
    main()
