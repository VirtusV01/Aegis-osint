import json
import pickle
from pathlib import Path

def load_meta(scan_dir: Path) -> dict:
    return json.loads((scan_dir / "meta.json").read_text(encoding="utf-8"))

def load_entities(scan_dir: Path) -> list[dict]:
    path = scan_dir / "entities.jsonl"
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def load_graph(scan_dir: Path):
    with (scan_dir / "graph.gpickle").open("rb") as f:
        return pickle.load(f)
