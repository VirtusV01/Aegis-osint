from __future__ import annotations

from typing import List
from .base import BaseModule, Entity, ModuleResult

class HTTPLiveModule(BaseModule):
    name = "sfp_http_live"
    description = "Live HTTP headers + simple tech hints for a website (authorized targets only)."
    produces = ["url", "hostname", "tag"]

    async def run(self, target: str) -> ModuleResult:
        entities: List[Entity] = []

        try:
            import aiohttp
        except Exception as e:
            entities.append(Entity(
                value=target, type="hostname", provenance=self.name, credibility=0.3,
                meta={"error": "aiohttp not installed. pip install aiohttp", "detail": str(e)}
            ))
            return ModuleResult(self.name, entities, None)

        # normalize URL
        url = target.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        entities.append(Entity(value=url, type="url", provenance=self.name, credibility=0.8, meta={"source": "http"}))

        headers_out = {}
        tech_tags = []

        try:
            timeout = aiohttp.ClientTimeout(total=12)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    headers_out = {k: v for k, v in resp.headers.items()}

                    server = headers_out.get("Server")
                    powered = headers_out.get("X-Powered-By")
                    if server:
                        tech_tags.append(f"server:{server}")
                    if powered:
                        tech_tags.append(f"powered_by:{powered}")

                    # basic security headers presence tags
                    sec_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
                    for h in sec_headers:
                        if h in headers_out:
                            tech_tags.append(f"has:{h}")

        except Exception as e:
            entities.append(Entity(
                value=url, type="url", provenance=self.name, credibility=0.35,
                meta={"error": "HTTP fetch failed", "detail": str(e)}
            ))
            return ModuleResult(self.name, entities, None)

        # turn tags into entities (Maltego-like “annotations”)
        for t in tech_tags:
            entities.append(Entity(value=t, type="tag", provenance=self.name, credibility=0.55, meta={"source": "headers"}))

        return ModuleResult(self.name, entities, {"headers": headers_out})
