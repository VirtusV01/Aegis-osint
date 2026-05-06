# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Name:         base (Aegis OSINT Core)
# Purpose:      Shared base classes for Aegis OSINT modules.
#
# Origin:       Inspired by SpiderFoot plugin model (MIT Licensed).
# Project:      SpiderFoot – https://github.com/smicallef/spiderfoot
#
# Adapted For:  Aegis OSINT – Unified OSINT Correlation Framework
# Maintainer:   Bhuvanesh Jayaraman
# Created:      14/11/2025
# Licence:      MIT
# -----------------------------------------------------------------------------

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List


@dataclass
class Entity:
    value: str
    type: str
    provenance: str
    credibility: float = 0.8
    meta: Dict[str, Any] | None = None


@dataclass
class ModuleResult:
    module_name: str
    entities: List[Entity]
    raw: Dict[str, Any] | None = None


class BaseModule(ABC):
    name: str = "base"
    description: str = ""
    produces: List[str] = []

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    async def run(self, target: str) -> ModuleResult:
        ...

    @staticmethod
    def serialise_entities(entities: List[Entity]) -> List[Dict[str, Any]]:
        ts = datetime.utcnow().isoformat() + "Z"
        rows = []
        for e in entities:
            d = asdict(e)
            d["timestamp"] = ts
            rows.append(d)
        return rows
