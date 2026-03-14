"""Automated responses REST endpoints."""

from fastapi import APIRouter, Query
from database.repository import get_responses, count_documents

router = APIRouter()


@router.get("")
async def list_responses(limit: int = Query(50, ge=1, le=200)):
    responses = await get_responses(limit=limit)
    return {"responses": responses, "total": len(responses)}


@router.get("/stats")
async def response_stats():
    total = await count_documents("responses")
    blocked = await count_documents("responses", {"status": "blocked"})
    monitoring = await count_documents("responses", {"status": "monitoring"})
    resolved = await count_documents("responses", {"status": "resolved"})
    return {
        "total": total,
        "blocked": blocked,
        "monitoring": monitoring,
        "resolved": resolved,
    }
