# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Name:         sfp_shodan (Aegis OSINT Version)
# Purpose:      Query Shodan for information related to the target (IP/domain).
#
# Original:     SpiderFoot plugin "sfp_shodan"
# Source:       https://github.com/smicallef/spiderfoot
# Author:       Steve Micallef
# Licence:      MIT
#
# Adapted For:  Aegis OSINT – Unified Correlation Framework
# Maintainer:   Bhuvanesh Jayaraman
# Created:      14/11/2025
# -----------------------------------------------------------------------------

from __future__ import annotations

from typing import List

# Make aiohttp OPTIONAL so the dashboard doesn't crash if it's missing
try:
    import aiohttp  # type: ignore
except ImportError:
    aiohttp = None  # allows module import without aiohttp installed

from .base import BaseModule, Entity, ModuleResult


class ShodanModule(BaseModule):
    name = "sfp_shodan"
    description = "Query Shodan for host exposure, ports, banners, and metadata."
    produces = ["ip", "service", "port", "tag", "hostname"]

    API_URL = "https://api.shodan.io/shodan/host/"

    async def run(self, target: str) -> ModuleResult:
        entities: List[Entity] = []

        # Graceful degradation: module loads but reports unavailable
        if aiohttp is None:
            entities.append(
                Entity(
                    value=target,
                    type="ip",
                    provenance=self.name,
                    credibility=0.2,
                    meta={"error": "aiohttp not installed; Shodan module unavailable"}
                )
            )
            return ModuleResult(self.name, entities, None)

        api_key = self.config.get("SHODAN_API_KEY")
        if not api_key:
            entities.append(
                Entity(
                    value=target,
                    type="ip",
                    provenance=self.name,
                    credibility=0.4,
                    meta={"error": "Missing SHODAN_API_KEY"}
                )
            )
            return ModuleResult(self.name, entities, None)

        url = f"{self.API_URL}{target}?key={api_key}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=15) as resp:
                    if resp.status != 200:
                        msg = await resp.text()
                        entities.append(
                            Entity(
                                value=target,
                                type="ip",
                                provenance=self.name,
                                credibility=0.4,
                                meta={"error": f"HTTP {resp.status}: {msg}"}
                            )
                        )
                        return ModuleResult(self.name, entities, None)

                    raw = await resp.json()

        except Exception as e:
            entities.append(
                Entity(
                    value=target,
                    type="ip",
                    provenance=self.name,
                    credibility=0.4,
                    meta={"error": str(e)}
                )
            )
            return ModuleResult(self.name, entities, None)

        ip = raw.get("ip_str", target)
        hostnames = raw.get("hostnames", [])
        tags = raw.get("tags", [])

        # main IP entity
        entities.append(
            Entity(
                value=ip,
                type="ip",
                provenance=self.name,
                credibility=0.9,
                meta={
                    "asn": raw.get("asn"),
                    "org": raw.get("org"),
                    "country": raw.get("country_name"),
                    "os": raw.get("os"),
                }
            )
        )

        # hostnames
        for h in hostnames:
            entities.append(
                Entity(
                    value=h,
                    type="hostname",
                    provenance=self.name,
                    credibility=0.8,
                    meta={}
                )
            )

        # tags
        for t in tags:
            entities.append(
                Entity(
                    value=t,
                    type="tag",
                    provenance=self.name,
                    credibility=0.7,
                    meta={}
                )
            )

        # service banners
        for item in raw.get("data", []):
            port = item.get("port")
            product = item.get("product") or "unknown"

            entities.append(
                Entity(
                    value=f"{ip}:{port}",
                    type="service",
                    provenance=self.name,
                    credibility=0.85,
                    meta={
                        "port": port,
                        "product": product,
                        "banner": item.get("data"),
                        "transport": item.get("transport"),
                    }
                )
            )

        return ModuleResult(self.name, entities, raw)
