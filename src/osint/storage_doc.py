import json
import pathlib
from typing import Iterable


def write_jsonl(path: str, items: Iterable[dict]) -> str:
    p = pathlib.Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for it in items: f.write(json.dumps(it, ensure_ascii=False) + "\n")
    return str(p)

def save_records(path: str, records):
    return write_jsonl(path, (r.to_dict() for r in records))

def save_entities(path: str, entities):
    return write_jsonl(path, (e.__dict__ for e in entities))
