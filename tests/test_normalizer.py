from osint.schemas import Record
from osint.normalizer import record_to_entities

def test_email_extraction():
    r = Record(source="web", fetched_at="now", text="Email me at alice@example.com")
    ents = record_to_entities(r)
    assert any(e.value == "alice@example.com" for e in ents)
