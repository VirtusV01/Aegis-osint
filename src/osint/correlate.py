import networkx as nx
from typing import List, Tuple
from .schemas import Record, Entity


def build_graph(
    records: List[Record],
    entities: List[Entity],
    credibility_threshold: float = 0.40,
) -> Tuple[nx.Graph, int]:
    """
    Build a correlation graph from records and entities.

    Entities whose credibility falls below *credibility_threshold* are excluded
    from the graph entirely (not added as nodes).  The count of those excluded
    entities is returned as *suppressed_count*.

    Every record-to-entity edge carries a ``weight`` equal to the average
    credibility of its two endpoints (record nodes are treated as having
    credibility 1.0 because they are the anchoring source data).

    Returns:
        (G, suppressed_count)
    """
    G = nx.Graph()
    suppressed_count = 0

    # Add record nodes with provenance metadata
    for r in records:
        rid = f"rec:{(r.url or r.source)}"
        G.add_node(
            rid,
            kind="record",
            source=r.source,
            fetched_at=r.fetched_at,
            activity=r.activity,
            agent=r.agent,
            record_id=r.record_id,
        )

    # Add entity nodes, filtering below threshold
    admitted: List[Entity] = []
    for e in entities:
        score = e.credibility if e.credibility is not None else 0.0
        if score < credibility_threshold:
            suppressed_count += 1
            continue
        admitted.append(e)
        nid = f"{e.type}:{e.value}"
        G.add_node(
            nid,
            kind="entity",
            type=e.type,
            provenance_source=e.provenance_source,
            provenance_activity=e.provenance_activity,
            provenance_agent=e.provenance_agent,
            credibility=e.credibility,
            first_seen=e.first_seen,
            last_seen=e.last_seen,
        )

    # Connect records to admitted entities; weight = avg credibility of endpoints
    for r in records:
        rid = f"rec:{(r.url or r.source)}"
        for e in [x for x in admitted if x.provenance_source == r.source]:
            nid = f"{e.type}:{e.value}"
            e_score = e.credibility if e.credibility is not None else 0.0
            # Record nodes have no scored credibility; treat as 1.0
            G.add_edge(
                rid,
                nid,
                rel="mentions",
                activity=e.provenance_activity,
                agent=e.provenance_agent,
                weight=round((1.0 + e_score) / 2.0, 4),
            )

    return G, suppressed_count
