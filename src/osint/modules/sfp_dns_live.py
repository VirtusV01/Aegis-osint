from __future__ import annotations

from typing import List
from .base import BaseModule, Entity, ModuleResult

class DNSLiveModule(BaseModule):
    name = "sfp_dns_live"
    description = "Live DNS enumeration (A/AAAA/MX/NS/TXT) for a domain (authorized targets only)."
    produces = ["domain", "ip", "mx", "name_server", "txt"]

    async def run(self, target: str) -> ModuleResult:
        entities: List[Entity] = []

        try:
            import dns.resolver  # dnspython
        except Exception as e:
            entities.append(Entity(
                value=target, type="domain", provenance=self.name, credibility=0.3,
                meta={"error": "dnspython not installed. pip install dnspython", "detail": str(e)}
            ))
            return ModuleResult(self.name, entities, None)

        resolver = dns.resolver.Resolver()
        entities.append(Entity(value=target, type="domain", provenance=self.name, credibility=0.8, meta={"source": "dns"}))

        def safe_query(rrtype: str):
            try:
                return resolver.resolve(target, rrtype)
            except Exception:
                return None

        # A
        ans = safe_query("A")
        if ans:
            for r in ans:
                entities.append(Entity(value=str(r), type="ip", provenance=self.name, credibility=0.75, meta={"rr": "A"}))

        # AAAA
        ans = safe_query("AAAA")
        if ans:
            for r in ans:
                entities.append(Entity(value=str(r), type="ip", provenance=self.name, credibility=0.75, meta={"rr": "AAAA"}))

        # MX
        ans = safe_query("MX")
        if ans:
            for r in ans:
                entities.append(Entity(value=str(r.exchange).rstrip("."), type="mx", provenance=self.name, credibility=0.7, meta={"rr": "MX", "priority": getattr(r, "preference", None)}))

        # NS
        ans = safe_query("NS")
        if ans:
            for r in ans:
                entities.append(Entity(value=str(r).rstrip("."), type="name_server", provenance=self.name, credibility=0.7, meta={"rr": "NS"}))

        # TXT
        ans = safe_query("TXT")
        if ans:
            for r in ans:
                txt = " ".join([b.decode(errors="ignore") if isinstance(b, bytes) else str(b) for b in getattr(r, "strings", [])]) \
                      if hasattr(r, "strings") else str(r)
                entities.append(Entity(value=txt, type="txt", provenance=self.name, credibility=0.55, meta={"rr": "TXT"}))

        return ModuleResult(self.name, entities, {"target": target})
