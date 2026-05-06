from __future__ import annotations

import asyncio
import json
import pickle
import re
from pathlib import Path
from typing import List, Type, Dict, Any
from uuid import uuid4
from datetime import datetime, timezone

import networkx as nx
from dotenv import load_dotenv
import os

from osint.modules.base import BaseModule, Entity, ModuleResult
from osint.modules.sfp_shodan import ShodanModule
from osint.services.credibility import compute_credibility
from osint.modules.sfp_whois_live import WhoisLiveModule
from osint.modules.sfp_dns_live import DNSLiveModule
from osint.modules.sfp_http_live import HTTPLiveModule


load_dotenv()

# ✅ Correct: load SHODAN_API_KEY from .env by *variable name*
API_CONFIG = {
    "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY")
}

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]

DATA_DIR = ROOT / "data" / "outputs"
DATA_DIR.mkdir(parents=True, exist_ok=True)

SCANS_DIR = DATA_DIR / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)

MODULE_REGISTRY: Dict[str, Type[BaseModule]] = {
    "sfp_shodan": ShodanModule,
    "sfp_whois_live": WhoisLiveModule,
    "sfp_dns_live": DNSLiveModule,
    "sfp_http_live": HTTPLiveModule,
}



def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def slugify(name: str) -> str:
    """
    Make filesystem-safe scan name:
    - spaces -> hyphen
    - allow a-z A-Z 0-9 . _ -
    - max 64 chars
    """
    name = (name or "").strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^a-zA-Z0-9._-]", "", name)
    return name[:64] if name else ""


def allocate_scan_id(desired: str | None) -> str:
    """
    If desired is provided, use it (slugified).
    If exists, append -2, -3...
    Else UUID.
    """
    if desired:
        base = slugify(desired)
        if base:
            cand = base
            i = 2
            while (SCANS_DIR / cand).exists():
                cand = f"{base}-{i}"
                i += 1
            return cand
    return str(uuid4())


def create_scan_session(scan_name: str | None = None) -> Dict[str, Any]:
    """
    Creates an empty scan folder + meta.json (no scan execution).
    Used for 'Create New Scan' (case workspace).
    """
    scan_id = allocate_scan_id(scan_name)
    scan_dir = SCANS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "scan_id": scan_id,
        "scan_name": scan_name or scan_id,
        "status": "created",
        "created_at": _utc_now().isoformat(),
        "target": "",
        "selected_modules": [],
        "notes": "",
    }
    (scan_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (scan_dir / "entities.jsonl").write_text("", encoding="utf-8")
    (scan_dir / "findings.jsonl").write_text("", encoding="utf-8")

    return {"scan_id": scan_id, "scan_dir": str(scan_dir)}


def append_finding(scan_dir: Path, finding: Dict[str, Any]) -> None:
    path = scan_dir / "findings.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(finding, ensure_ascii=False) + "\n")


def make_finding(
    *,
    scan_id: str,
    module: str,
    event_type: str,
    value: str,
    entity_type: str | None = None,
    confidence: float | None = None,
    evidence: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    return {
        "finding_id": str(uuid4()),
        "scan_id": scan_id,
        "ts": _utc_now().isoformat(),
        "module": module,
        "event_type": event_type,
        "value": value,
        "entity_type": entity_type,
        "confidence": confidence,
        "evidence": evidence or {},
    }


async def run_scan(target: str, modules: List[str], scan_name: str | None = None) -> Dict[str, Any]:
    scan_id = allocate_scan_id(scan_name)
    scan_dir = SCANS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    started_at = _utc_now()

    selected = [m for m in modules if m in MODULE_REGISTRY]
    if not selected:
        meta = {
            "scan_id": scan_id,
            "scan_name": scan_name or scan_id,
            "target": target,
            "modules": modules,
            "selected_modules": [],
            "started_at": started_at.isoformat(),
            "finished_at": _utc_now().isoformat(),
            "duration_seconds": 0.0,
            "status": "failed",
            "error": "no valid modules",
        }
        (scan_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="scanner",
            event_type="ERROR",
            value="no valid modules selected",
            evidence={"provided_modules": modules}
        ))
        return {"error": "no valid modules", "scan_id": scan_id}

    meta = {
        "scan_id": scan_id,
        "scan_name": scan_name or scan_id,
        "target": target,
        "modules": modules,
        "selected_modules": selected,
        "started_at": started_at.isoformat(),
        "status": "running",
    }
    (scan_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    append_finding(scan_dir, make_finding(
        scan_id=scan_id,
        module="scanner",
        event_type="SCAN_STARTED",
        value=f"Scan started for target: {target}",
        evidence={"selected_modules": selected, "scan_name": scan_name or scan_id}
    ))

    instances: List[BaseModule] = [MODULE_REGISTRY[name](config=API_CONFIG) for name in selected]

    try:
        for name in selected:
            append_finding(scan_dir, make_finding(
                scan_id=scan_id,
                module=name,
                event_type="MODULE_STARTED",
                value=f"Module started: {name}"
            ))

        results: List[ModuleResult] = await asyncio.gather(*[m.run(target) for m in instances])

        for name in selected:
            append_finding(scan_dir, make_finding(
                scan_id=scan_id,
                module=name,
                event_type="MODULE_FINISHED",
                value=f"Module finished: {name}"
            ))

    except Exception as e:
        finished_at = _utc_now()
        meta.update({
            "finished_at": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
            "status": "failed",
            "error": repr(e),
        })
        (scan_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="scanner",
            event_type="ERROR",
            value="Scan failed during module execution",
            evidence={"error": repr(e)}
        ))
        return {"error": "scan failed", "scan_id": scan_id, "details": repr(e)}

    # Collect serialized entities
    serialized: List[Dict[str, Any]] = []
    for res in results:
        serialized.extend(BaseModule.serialise_entities(res.entities))

    # Compute credibility across whole set
    serialized = compute_credibility(serialized)

    # Write entities.jsonl
    entities_path = scan_dir / "entities.jsonl"
    with entities_path.open("w", encoding="utf-8") as fh:
        for row in serialized:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    # Findings: ENTITY_FOUND
    for row in serialized:
        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module=str(row.get("provenance", "unknown")),
            event_type="ENTITY_FOUND",
            value=str(row.get("value")),
            entity_type=str(row.get("type")),
            confidence=row.get("credibility_score"),
        ))

    # Graph build
    G = nx.Graph()
    G.add_node(target, kind="seed")

    for row in serialized:
        val = row.get("value")
        etype = row.get("type")
        if val is None:
            continue
        G.add_node(val, kind="entity", type=etype)
        G.add_edge(target, val, module=row.get("provenance", "unknown"))

        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="correlate",
            event_type="LINK_CREATED",
            value=f"{target} -> {val}",
            evidence={"edge_module": row.get("provenance", "unknown")}
        ))

    graph_path = scan_dir / "graph.gpickle"
    with graph_path.open("wb") as fh:
        pickle.dump(G, fh)

    finished_at = _utc_now()
    meta.update({
        "finished_at": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "status": "completed",
        "entities_added": len(serialized),
        "outputs": {
            "entities": str(entities_path),
            "graph": str(graph_path),
            "findings": str(scan_dir / "findings.jsonl"),
        }
    })
    (scan_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    append_finding(scan_dir, make_finding(
        scan_id=scan_id,
        module="scanner",
        event_type="SCAN_FINISHED",
        value=f"Scan finished. entities_added={len(serialized)} duration={meta['duration_seconds']:.2f}s"
    ))

    return {
        "scan_id": scan_id,
        "target": target,
        "modules": selected,
        "entities_added": len(serialized),
        "scan_dir": str(scan_dir),
    }
