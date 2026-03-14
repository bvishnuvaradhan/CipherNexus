"""Alerts REST endpoints."""

from fastapi import APIRouter, Query
from typing import Optional
from database.repository import get_alerts, get_threat_level, count_documents

router = APIRouter()


@router.get("")
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
):
    alerts = await get_alerts(limit=limit, severity=severity)
    return {"alerts": alerts, "total": len(alerts)}


@router.get("/threat-level")
async def threat_level():
    return await get_threat_level()


@router.get("/stats")
async def alert_stats():
    total = await count_documents("alerts")
    active = await count_documents("alerts", {"status": "active"})
    critical = await count_documents("alerts", {"severity": "critical"})
    high = await count_documents("alerts", {"severity": "high"})
    medium = await count_documents("alerts", {"severity": "medium"})
    return {
        "total": total,
        "active": active,
        "critical": critical,
        "high": high,
        "medium": medium,
        "resolved": total - active,
    }
