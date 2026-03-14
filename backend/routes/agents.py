"""Agent status REST endpoints."""

import asyncio

from fastapi import APIRouter, Request
from database.repository import get_agent_activity_metrics

router = APIRouter()


@router.get("")
async def list_agents(request: Request):
    orchestrator = request.app.state.orchestrator
    statuses = orchestrator.get_all_agent_statuses()

    # Merge in persisted metrics so status survives process restarts.
    persisted = await asyncio.gather(*[
        get_agent_activity_metrics(agent.get("name", ""))
        for agent in statuses
    ])
    merged = []
    for status, metric in zip(statuses, persisted):
        item = dict(status)
        item["threat_count"] = max(int(item.get("threat_count", 0) or 0), int(metric.get("threat_count", 0) or 0))
        item["confidence_avg"] = max(float(item.get("confidence_avg", 0.0) or 0.0), float(metric.get("confidence_avg", 0.0) or 0.0))
        merged.append(item)
    return {"agents": merged}


@router.get("/{agent_name}")
async def get_agent(agent_name: str, request: Request):
    orchestrator = request.app.state.orchestrator
    statuses = orchestrator.get_all_agent_statuses()
    for agent in statuses:
        if agent["name"].lower() == agent_name.lower():
            metric = await get_agent_activity_metrics(agent.get("name", ""))
            item = dict(agent)
            item["threat_count"] = max(int(item.get("threat_count", 0) or 0), int(metric.get("threat_count", 0) or 0))
            item["confidence_avg"] = max(float(item.get("confidence_avg", 0.0) or 0.0), float(metric.get("confidence_avg", 0.0) or 0.0))
            return item
    return {"error": "Agent not found"}
