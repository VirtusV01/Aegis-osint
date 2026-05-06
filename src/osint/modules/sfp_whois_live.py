from __future__ import annotations

from typing import List
from .base import BaseModule, Entity, ModuleResult

class WhoisLiveModule(BaseModule):
    name = "sfp_whois_live"
    description = "Live WHOIS lookup for a domain (authorized targets only)."
    produces = ["domain", "org", "registrar", "email", "name_server"]

    async def run(self, target: str) -> ModuleResult:
        entities: List[Entity] = []

        # Lazy import so missing libs don't crash app
        try:
            import whois  # python-whois
        except Exception as e:
            entities.append(Entity(
                value=target, type="domain", provenance=self.name, credibility=0.3,
                meta={"error": "python-whois not installed. pip install python-whois", "detail": str(e)}
            ))
            return ModuleResult(self.name, entities, None)

        try:
            w = whois.whois(target)
        except Exception as e:
            entities.append(Entity(
                value=target, type="domain", provenance=self.name, credibility=0.35,
                meta={"error": "WHOIS lookup failed", "detail": str(e)}
            ))
            return ModuleResult(self.name, entities, None)

        # Target entity
        entities.append(Entity(
            value=target, type="domain", provenance=self.name, credibility=0.8,
            meta={"source": "whois"}
        ))

        # Registrar / Org / Emails / Name servers (best-effort)
        registrar = getattr(w, "registrar", None)
        if registrar:
            entities.append(Entity(value=str(registrar), type="registrar", provenance=self.name, credibility=0.7, meta={}))

        org = getattr(w, "org", None) or getattr(w, "organization", None)
        if org:
            entities.append(Entity(value=str(org), type="org", provenance=self.name, credibility=0.7, meta={}))

        emails = getattr(w, "emails", None)
        if emails:
            if isinstance(emails, str):
                emails = [emails]
            for em in list(set([str(x) for x in emails if x])):
                entities.append(Entity(value=em, type="email", provenance=self.name, credibility=0.65, meta={"source": "whois"}))

        ns = getattr(w, "name_servers", None)
        if ns:
            if isinstance(ns, str):
                ns = [ns]
            for n in list(set([str(x).strip().lower() for x in ns if x])):
                entities.append(Entity(value=n, type="name_server", provenance=self.name, credibility=0.6, meta={"source": "whois"}))

        return ModuleResult(self.name, entities, {"whois": str(w)})
