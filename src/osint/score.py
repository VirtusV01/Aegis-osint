from .schemas import Record, Entity

def credibility(record: Record) -> float:
    # toy heuristic for IPR: WHOIS > WEB content
    base = 0.6 if record.source == "web" else 0.8 if record.source == "whois" else 0.5
    bonus = 0.1 if record.title else 0.0
    return min(1.0, base + bonus)

def entity_confidence(entity: Entity) -> float:
    if entity.type in {"email","domain"}: return 0.85
    return 0.65
