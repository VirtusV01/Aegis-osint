from typing import List
from .schemas import Record, Entity
import re, tldextract

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

def record_to_entities(r: Record) -> List[Entity]:
    ents: List[Entity] = []

    # Domain extracted from URL
    if r.url:
        d = tldextract.extract(r.url)
        if d.registered_domain:
            e = Entity(
                type="domain",
                value=d.registered_domain,
                provenance_source=r.source,
                provenance_activity="normalizer",
                provenance_agent="aegis-osint",
            )
            e.touch_seen(r.fetched_at)
            ents.append(e)

    # Emails from text + whois blob
    text = (r.text or "") + " " + str(r.whois or "")
    for m in set(EMAIL_RE.findall(text)):
        e = Entity(
            type="email",
            value=m,
            provenance_source=r.source,
            provenance_activity="normalizer",
            provenance_agent="aegis-osint",
        )
        e.touch_seen(r.fetched_at)
        ents.append(e)

    return ents
