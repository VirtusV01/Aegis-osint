"""
nlp.py – Entity extraction module for OSINT framework.

Responsible for:
- Extracting entities from normalised text records
- Supporting IOC-style entities (IP, domain, email, URL, hashes)
- Supporting semantic entities via spaCy (PERSON, ORG, LOCATION, DATE)
- Returning provenance-aware entity objects for graph correlation
"""

from __future__ import annotations

import re
from typing import Dict, List, Any

import spacy

# ---------- 1. spaCy model loader ----------

_SPACY_MODEL_NAME = "en_core_web_sm"
_NLP = None


def get_spacy_model():
    """
    Lazy-load spaCy model (so tests can mock easily).
    """
    global _NLP
    if _NLP is None:
        _NLP = spacy.load(_SPACY_MODEL_NAME)
    return _NLP


# ---------- 2. Regex patterns for IOCs ----------

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?!$)|$)){4}\b"
)

RE_IPV6 = re.compile(
    r"\b(?:(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4})\b"
)

RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

RE_URL = re.compile(
    r"\bhttps?://[^\s\"'<>]+"
)

RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Simple username pattern: words with @ or underscores/digits
RE_USERNAME = re.compile(
    r"\b@[A-Za-z0-9_]{3,32}\b|\b[A-Za-z][A-Za-z0-9_]{2,31}\b"
)


# ---------- 3. Helpers to build entity dict ----------

def _make_entity(
    record: Dict[str, Any],
    entity_index: int,
    ent_type: str,
    value: str,
    start: int,
    end: int,
    sentence_id: int = 0,
) -> Dict[str, Any]:
    """
    Build a provenance-aware entity object.
    """
    return {
        "entity_id": f"{record['record_id']}#e{entity_index}",
        "record_id": record["record_id"],
        "type": ent_type,
        "value": value,
        "start_char": start,
        "end_char": end,
        "sentence_id": sentence_id,
        "source": record.get("source"),
        "source_url": record.get("source_url"),
        "collected_at": record.get("collected_at"),
    }


# ---------- 4. Core extraction function ----------

def extract_entities_from_text(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Main entry point for entity extraction.

    Parameters
    ----------
    record : dict
        Normalised record with at least:
        - record_id (str)
        - text (str)
        - source, source_url, collected_at (optional but recommended)

    Returns
    -------
    List[dict]
        List of entity objects with provenance.
    """
    text = record.get("text") or ""
    entities: List[Dict[str, Any]] = []
    entity_index = 0

    # ---- 4.1 Regex-based IOCs ----
    for match in RE_IPV4.finditer(text):
        entities.append(
            _make_entity(record, entity_index, "IPV4", match.group(), match.start(), match.end())
        )
        entity_index += 1

    for match in RE_IPV6.finditer(text):
        entities.append(
            _make_entity(record, entity_index, "IPV6", match.group(), match.start(), match.end())
        )
        entity_index += 1

    for match in RE_EMAIL.finditer(text):
        value = match.group().lower()
        entities.append(
            _make_entity(record, entity_index, "EMAIL", value, match.start(), match.end())
        )
        entity_index += 1

    for match in RE_URL.finditer(text):
        entities.append(
            _make_entity(record, entity_index, "URL", match.group(), match.start(), match.end())
        )
        entity_index += 1

    for match in RE_DOMAIN.finditer(text):
        value = match.group().lower()
        # Avoid double-counting domains that are inside URLs/emails (cheap heuristic)
        if "://" in value or "@" in value:
            continue
        entities.append(
            _make_entity(record, entity_index, "DOMAIN", value, match.start(), match.end())
        )
        entity_index += 1

    for match in RE_MD5.finditer(text):
        entities.append(
            _make_entity(record, entity_index, "HASH_MD5", match.group().lower(), match.start(), match.end())
        )
        entity_index += 1

    for match in RE_SHA1.finditer(text):
        entities.append(
            _make_entity(record, entity_index, "HASH_SHA1", match.group().lower(), match.start(), match.end())
        )
        entity_index += 1

    for match in RE_SHA256.finditer(text):
        entities.append(
            _make_entity(record, entity_index, "HASH_SHA256", match.group().lower(), match.start(), match.end())
        )
        entity_index += 1

    # ---- 4.2 spaCy-based semantic entities ----
    nlp = get_spacy_model()
    doc = nlp(text)

    for sent_id, sent in enumerate(doc.sents):
        for ent in sent.ents:
            ent_type = None
            if ent.label_ == "PERSON":
                ent_type = "PERSON"
            elif ent.label_ in ("ORG", "NORP"):
                ent_type = "ORG"
            elif ent.label_ in ("GPE", "LOC", "FAC"):
                ent_type = "LOCATION"
            elif ent.label_ in ("DATE", "TIME"):
                ent_type = "DATE"

            if ent_type:
                entities.append(
                    _make_entity(
                        record,
                        entity_index,
                        ent_type,
                        ent.text.strip(),
                        ent.start_char,
                        ent.end_char,
                        sentence_id=sent_id,
                    )
                )
                entity_index += 1

        # ---- 4.3 Username-like tokens within each sentence ----
        for match in RE_USERNAME.finditer(sent.text):
            raw = match.group()
            # basic filter: skip if it's clearly an email/hash/domain length etc.
            if len(raw) < 3 or "@" in raw and not raw.startswith("@"):
                continue
            entities.append(
                _make_entity(
                    record,
                    entity_index,
                    "USERNAME",
                    raw.lstrip("@"),
                    sent.start_char + match.start(),
                    sent.start_char + match.end(),
                    sentence_id=sent_id,
                )
            )
            entity_index += 1

    # ---- 4.4 De-duplicate per (type, value, record_id) ----
    unique: Dict[tuple, Dict[str, Any]] = {}
    for ent in entities:
        key = (ent["record_id"], ent["type"], ent["value"])
        if key not in unique:
            unique[key] = ent

    # Reassign entity_id with contiguous indexes
    deduped_entities: List[Dict[str, Any]] = []
    for idx, ent in enumerate(unique.values()):
        ent["entity_id"] = f"{record['record_id']}#e{idx}"
        deduped_entities.append(ent)

    return deduped_entities


# ---------- 5. Batch wrapper ----------

def process_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Take a list of normalised records and attach `entities` list to each.
    """
    result = []
    for rec in records:
        rec_copy = dict(rec)
        rec_copy["entities"] = extract_entities_from_text(rec_copy)
        result.append(rec_copy)
    return result


if __name__ == "__main__":
    # Simple manual test (you can replace with pytest)
    sample = {
        "record_id": "rec_demo",
        "source": "sim_web",
        "source_url": "https://example.com",
        "collected_at": "2025-11-30T10:00:00Z",
        "text": "Hacker john_doe98 emailed admin@evilcorp.co.uk from 203.0.113.5 on 12 Nov 2025.",
    }
    ents = extract_entities_from_text(sample)
    for e in ents:
        print(e)
