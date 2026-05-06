import json
from loguru import logger

from .schemas import Record
from .normalizer import record_to_entities
from .nlp import extract_entities_from_text   # <- use new NLP
from .dedup import dedup_entities
from .correlate import build_graph
from .storage_graph import save_graph
from .storage_doc import save_entities


def record_to_nlp_dict(r: Record) -> dict:
    """
    Convert Record (Pydantic) -> dict structure expected by extract_entities_from_text().
    Adjust keys if your Record schema differs.
    """
    # Pydantic v2: model_dump(); v1: dict()
    if hasattr(r, "model_dump"):
        raw = r.model_dump()
    else:
        raw = r.dict()

    return {
        "record_id": raw.get("record_id") or raw.get("id"),
        "source": raw.get("source"),
        "source_url": raw.get("source_url"),
        "collected_at": raw.get("collected_at"),
        "text": raw.get("text") or "",
    }


def run_demo_synthetic():
    logger.info("Loading synthetic dataset...")
    with open("data/samples/synthetic_records.jsonl", "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f]

    # Build Record objects
    records = [Record(**d) for d in data]

    logger.info("Extracting entities...")
    entities = []

    for r in records:
        # 1) Old structured field extraction (domains, IPs, etc from dedicated fields)
        entities += record_to_entities(r)

        # 2) New NLP-based extraction from free-text
        nlp_record = record_to_nlp_dict(r)
        entities += extract_entities_from_text(nlp_record)

    # De-duplicate across all records
    entities = dedup_entities(entities)

    logger.info("Building graph...")
    G = build_graph(records, entities)

    logger.info(f"Graph built with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")
    logger.info(f"Total unique entities: {len(entities)}")

    save_entities("data/outputs/synthetic_entities.jsonl", entities)
    save_graph("data/outputs/synthetic_graph.gpickle", G)

    logger.success("Synthetic pipeline run complete!")


if __name__ == "__main__":
    run_demo_synthetic()
