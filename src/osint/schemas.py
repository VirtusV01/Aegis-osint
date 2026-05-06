from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import uuid


@dataclass
class Record:
    # Who/where this record came from (web/social/whois/paste/etc.)
    source: str

    # When it was fetched (string from JSONL, ISO8601)
    fetched_at: str

    # Original content fields
    url: Optional[str] = None
    title: Optional[str] = None
    text: Optional[str] = None
    whois: Optional[Dict[str, Any]] = None

    # Provenance-style metadata
    activity: str = "collect"           # what pipeline step produced this record
    agent: str = "aegis-osint"          # which system/agent collected it
    raw_source_type: Optional[str] = None   # e.g. "http_html", "whois_text", "api_json"

    # Stable ID for tracking in graphs / logs
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Extra metadata if needed
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Entity:
    # Core identity
    type: str          # "person", "org", "domain", "email", "ip", ...
    value: str

    # Provenance triple components
    provenance_source: str             # which source stream: "web", "whois", "social", ...
    provenance_activity: str = "extract"   # which step/module created this entity
    provenance_agent: str = "aegis-osint"  # which system/agent produced it

    # Credibility & metadata (to be filled by scoring later)
    credibility: Optional[float] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    # Temporal footprint
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def touch_seen(self, ts: Optional[str] = None) -> None:
        """Update first_seen / last_seen with a timestamp (UTC if not provided)."""
        if ts is None:
            ts = datetime.now(timezone.utc).isoformat()
        if self.first_seen is None:
            self.first_seen = ts
        self.last_seen = ts

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
