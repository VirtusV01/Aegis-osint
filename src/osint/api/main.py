from __future__ import annotations

import asyncio
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any

from osint.services.scanner import run_scan, MODULE_REGISTRY


app = FastAPI(
    title="Aegis OSINT API",
    version="1.0",
    description="Backend for Aegis OSINT investigation framework"
)


class ScanRequest(BaseModel):
    target: str
    modules: List[str]


class ScanResponse(BaseModel):
    target: str
    modules: List[str]
    entities_added: int


@app.get("/modules")
def list_modules() -> List[Dict[str, Any]]:
    return [
        {
            "name": name,
            "description": cls.description,
            "produces": cls.produces
        }
        for name, cls in MODULE_REGISTRY.items()
    ]


@app.post("/scans/start", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    summary = await run_scan(req.target, req.modules)

    return ScanResponse(
        target=summary["target"],
        modules=summary["modules"],
        entities_added=summary["entities_added"]
    )
