from __future__ import annotations

import json
import pickle
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from uuid import uuid4

import networkx as nx

# ✅ NEW: credibility
from osint.services.credibility import compute_credibility


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    evidence: Dict[str, Any] | None = None,
    confidence: float | None = None
) -> Dict[str, Any]:
    return {
        "finding_id": str(uuid4()),
        "scan_id": scan_id,
        "ts": _utc_now_iso(),
        "module": module,
        "event_type": event_type,
        "value": value,
        "entity_type": entity_type,
        "confidence": confidence,
        "evidence": evidence or {},
    }


def load_meta(scan_dir: Path) -> Dict[str, Any]:
    return json.loads((scan_dir / "meta.json").read_text(encoding="utf-8"))


def load_graph(scan_dir: Path) -> nx.Graph:
    with (scan_dir / "graph.gpickle").open("rb") as f:
        return pickle.load(f)


def save_graph(scan_dir: Path, G: nx.Graph) -> None:
    with (scan_dir / "graph.gpickle").open("wb") as f:
        pickle.dump(G, f)


def load_entities(scan_dir: Path) -> List[Dict[str, Any]]:
    path = scan_dir / "entities.jsonl"
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def save_entities(scan_dir: Path, entities: List[Dict[str, Any]]) -> None:
    path = scan_dir / "entities.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for row in entities:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _entity_key(e: Dict[str, Any]) -> Tuple[str, str]:
    return (str(e.get("type", "")), str(e.get("value", "")))


def upsert_entities(existing: List[Dict[str, Any]], new_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {_entity_key(e) for e in existing}
    for n in new_items:
        k = _entity_key(n)
        if k not in seen:
            existing.append(n)
            seen.add(k)
    return existing


# ----------------------------
# Transform 1: WHOIS (synthetic)
# ----------------------------
def whois_transform_synth(scan_dir: Path, selected_entity: str) -> Dict[str, Any]:
    meta = load_meta(scan_dir)
    scan_id = meta["scan_id"]

    append_finding(scan_dir, make_finding(
        scan_id=scan_id,
        module="transform_whois_synth",
        event_type="TRANSFORM_STARTED",
        value=f"WHOIS transform started for {selected_entity}"
    ))

    base = selected_entity.split(":")[0].lower()
    base = re.sub(r"[^a-z0-9\.-]", "", base)
    org = f"{base.split('.')[0].capitalize()} Holdings Ltd"
    registrar = "ExampleRegistrar Inc"
    abuse_email = f"abuse@{base}"

    new_entities = [
        {"value": org, "type": "org", "provenance": "whois_synth", "credibility": 0.75, "meta": {"from": selected_entity}},
        {"value": registrar, "type": "registrar", "provenance": "whois_synth", "credibility": 0.70, "meta": {"from": selected_entity}},
        {"value": abuse_email, "type": "email", "provenance": "whois_synth", "credibility": 0.80, "meta": {"from": selected_entity}},
    ]

    G = load_graph(scan_dir)
    entities = load_entities(scan_dir)

    if not G.has_node(selected_entity):
        G.add_node(selected_entity, kind="entity")

    for e in new_entities:
        val = e["value"]
        etype = e["type"]
        G.add_node(val, kind="entity", type=etype)
        G.add_edge(selected_entity, val, module="whois_synth")

        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="transform_whois_synth",
            event_type="ENTITY_FOUND",
            value=val,
            entity_type=etype,
            confidence=e.get("credibility"),
            evidence={"from": selected_entity}
        ))
        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="transform_whois_synth",
            event_type="LINK_CREATED",
            value=f"{selected_entity} -> {val}",
            evidence={"relation": "whois_synth"}
        ))

    # ✅ upsert + credibility + save
    entities = upsert_entities(entities, new_entities)
    entities = compute_credibility(entities)
    save_entities(scan_dir, entities)
    save_graph(scan_dir, G)

    append_finding(scan_dir, make_finding(
        scan_id=scan_id,
        module="transform_whois_synth",
        event_type="TRANSFORM_FINISHED",
        value=f"WHOIS transform finished for {selected_entity}"
    ))

    return {"added_entities": len(new_entities), "transform": "whois_synth"}


# ----------------------------
# Transform 2: Related entities from synthetic records.jsonl
# ----------------------------
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def related_entities_transform_from_records(
    scan_dir: Path,
    selected_entity: str,
    records_path: Path,
) -> Dict[str, Any]:
    meta = load_meta(scan_dir)
    scan_id = meta["scan_id"]

    append_finding(scan_dir, make_finding(
        scan_id=scan_id,
        module="transform_related_records",
        event_type="TRANSFORM_STARTED",
        value=f"Related-entities transform started for {selected_entity}"
    ))

    if not records_path.exists():
        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="transform_related_records",
            event_type="ERROR",
            value="records.jsonl missing",
            evidence={"expected_path": str(records_path)}
        ))
        return {"added_entities": 0, "error": "records.jsonl missing"}

    G = load_graph(scan_dir)
    entities = load_entities(scan_dir)

    if not G.has_node(selected_entity):
        G.add_node(selected_entity, kind="entity")

    found: List[Dict[str, Any]] = []

    with records_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)

            text = " ".join([
                str(rec.get("url", "")),
                str(rec.get("content", "")),
                str(rec.get("text", "")),
                str(rec.get("title", "")),
            ])

            if selected_entity.lower() not in text.lower():
                continue

            emails = set(EMAIL_RE.findall(text))
            ips = set(IP_RE.findall(text))

            for em in emails:
                found.append({"value": em, "type": "email", "provenance": "records_synth", "credibility": 0.65, "meta": {"match": selected_entity}})
            for ip in ips:
                found.append({"value": ip, "type": "ip", "provenance": "records_synth", "credibility": 0.60, "meta": {"match": selected_entity}})

    # Deduplicate
    uniq = {}
    for e in found:
        uniq[_entity_key(e)] = e
    new_entities = list(uniq.values())

    added_edges = 0
    for e in new_entities:
        val = e["value"]
        etype = e["type"]
        G.add_node(val, kind="entity", type=etype)

        if not G.has_edge(selected_entity, val):
            G.add_edge(selected_entity, val, module="records_synth")
            added_edges += 1

        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="transform_related_records",
            event_type="ENTITY_FOUND",
            value=val,
            entity_type=etype,
            confidence=e.get("credibility"),
            evidence={"matched_on": selected_entity}
        ))
        append_finding(scan_dir, make_finding(
            scan_id=scan_id,
            module="transform_related_records",
            event_type="LINK_CREATED",
            value=f"{selected_entity} -> {val}",
            evidence={"relation": "cooccur_records"}
        ))

    # ✅ upsert + credibility + save
    entities = upsert_entities(entities, new_entities)
    entities = compute_credibility(entities)
    save_entities(scan_dir, entities)
    save_graph(scan_dir, G)

    append_finding(scan_dir, make_finding(
        scan_id=scan_id,
        module="transform_related_records",
        event_type="TRANSFORM_FINISHED",
        value=f"Related-entities transform finished for {selected_entity} (added={len(new_entities)})"
    ))

    return {"added_entities": len(new_entities), "added_edges": added_edges, "transform": "related_records"}
