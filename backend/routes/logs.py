"""Logs REST endpoints."""

from fastapi import APIRouter, Query
from database.repository import get_logs, get_agent_messages, count_documents

router = APIRouter()


@router.get("")
async def list_logs(limit: int = Query(100, ge=1, le=500)):
    logs = await get_logs(limit=limit)
    return {"logs": logs, "total": len(logs)}


@router.get("/agent-messages")
async def list_agent_messages(limit: int = Query(50, ge=1, le=200)):
    messages = await get_agent_messages(limit=limit)
    return {"messages": messages, "total": len(messages)}
