from osint.schemas import Entity
from osint.dedup import dedup_entities

def test_dedup():
    ents = [
        Entity(type="email", value="a@example.com", provenance="web"),
        Entity(type="email", value="a@example.com", provenance="whois"),
    ]
    out = dedup_entities(ents)
    assert len(out) == 1
