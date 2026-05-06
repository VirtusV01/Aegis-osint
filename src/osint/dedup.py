from typing import List
from rapidfuzz import process, fuzz
from .schemas import Entity


def dedup_entities(entities: List[Entity], score_cutoff: int = 90) -> List[Entity]:
    by_type = {}
    for e in entities:
        by_type.setdefault(e.type, []).append(e)

    out: List[Entity] = []

    for t, ents in by_type.items():
        values = [e.value for e in ents]
        keep: List[str] = []

        for v in values:
            if not keep:
                keep.append(v)
                continue
            match, _, s = process.extractOne(v, keep, scorer=fuzz.token_sort_ratio)
            if s < score_cutoff:
                keep.append(v)

        # rebuild entities with merged provenance info
        prov_source = {e.value: e.provenance_source for e in ents}
        first_seen = {e.value: e.first_seen for e in ents if e.first_seen}
        last_seen = {e.value: e.last_seen for e in ents if e.last_seen}

        for v in keep:
            e = Entity(
                type=t,
                value=v,
                provenance_source=prov_source.get(v, "mixed"),
                provenance_activity="dedup",
                provenance_agent="aegis-osint",
            )
            # keep any existing timestamps if present
            if first_seen.get(v):
                e.first_seen = first_seen[v]
            if last_seen.get(v):
                e.last_seen = last_seen[v]
            out.append(e)

    return out
