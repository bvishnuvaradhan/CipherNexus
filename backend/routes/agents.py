"""Agent status REST endpoints."""

import asyncio
from typing import Any, Dict, List

from fastapi import APIRouter, Request
from database.repository import get_agent_activity_metrics, persist_agent_runtime_metrics

router = APIRouter()


AGENT_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "Sentry",
        "role": "Network Defense",
        "responsibilities": [
            "Monitor network traffic",
            "Detect traffic spikes",
            "Identify port scans",
            "Flag suspicious IPs",
        ],
    },
    {
        "name": "Detective",
        "role": "Log Intelligence",
        "responsibilities": [
            "Analyze login attempts",
            "Detect brute force attacks",
            "Flag abnormal login locations",
            "Analyze system logs",
        ],
    },
    {
        "name": "Commander",
        "role": "Decision Engine",
        "responsibilities": [
            "Correlate signals from Sentry & Detective",
            "Determine threat severity",
            "Initiate mitigation actions",
            "Generate XAI reasoning paths",
        ],
    },
    {
        "name": "Threat Intelligence",
        "role": "Threat Intelligence",
        "responsibilities": [
            "Monitor IOC and reputation feeds",
            "Correlate IPs with malicious infrastructure",
            "Track CVE and reputation context",
            "Reduce false positives with external intel",
        ],
    },
    {
        "name": "Anomaly Detection",
        "role": "Behavioral Analytics",
        "responsibilities": [
            "Detect behavioral anomalies",
            "Score suspicious events with ML",
            "Identify unknown attack patterns",
            "Provide anomaly confidence",
        ],
    },
    {
        "name": "Response Automation",
        "role": "Defensive Execution",
        "responsibilities": [
            "Execute containment actions",
            "Block malicious IPs",
            "Trigger notifications",
            "Track execution outcomes",
        ],
    },
    {
        "name": "Forensics",
        "role": "Incident Investigation",
        "responsibilities": [
            "Reconstruct attack timelines",
            "Summarize incident evidence",
            "Generate forensic notes",
            "Support future tuning",
        ],
    },
]


async def _build_agent_payloads(orchestrator) -> List[Dict[str, Any]]:
    live_statuses = orchestrator.get_all_agent_statuses()
    live_by_name = {a.get("name"): a for a in live_statuses}

    await asyncio.gather(*[
        persist_agent_runtime_metrics(status)
        for status in live_statuses
        if status.get("name")
    ])

    persisted = await asyncio.gather(*[
        get_agent_activity_metrics(agent["name"])
        for agent in AGENT_CATALOG
    ])
    persisted_by_name = {
        agent["name"]: metric
        for agent, metric in zip(AGENT_CATALOG, persisted)
    }

    merged: List[Dict[str, Any]] = []
    for agent in AGENT_CATALOG:
        name = agent["name"]
        live = live_by_name.get(name, {})
        metric = persisted_by_name.get(name, {})

        item = {
            "name": name,
            "role": agent.get("role"),
            "responsibilities": agent.get("responsibilities", []),
            "status": "offline",
            "threat_count": 0,
            "confidence_avg": 0.0,
            "uptime_seconds": 0,
            "last_action": None,
            "last_action_time": None,
            "has_live_status": False,
        }
        item.update(live)
        item["has_live_status"] = bool(live)
        item["threat_count"] = max(int(item.get("threat_count", 0) or 0), int(metric.get("threat_count", 0) or 0))
        item["total_threats_detected"] = max(
            int(item.get("total_threats_detected", item.get("threat_count", 0)) or 0),
            int(metric.get("total_threats_detected", 0) or 0),
            int(item.get("threat_count", 0) or 0),
        )
        item["confidence_avg"] = max(
            float(item.get("confidence_avg", 0.0) or 0.0),
            float(metric.get("confidence_avg", 0.0) or 0.0),
        )
        item["uptime_seconds"] = max(
            int(item.get("uptime_seconds", 0) or 0),
            int(metric.get("uptime_seconds", 0) or 0),
        )
        item["last_action"] = item.get("last_action") or metric.get("last_action")
        item["last_action_time"] = item.get("last_action_time") or metric.get("last_action_time")
        merged.append(item)

    return merged


@router.get("")
async def list_agents(request: Request):
    orchestrator = request.app.state.orchestrator
    return {"agents": await _build_agent_payloads(orchestrator)}


@router.get("/{agent_name}")
async def get_agent(agent_name: str, request: Request):
    orchestrator = request.app.state.orchestrator
    agents = await _build_agent_payloads(orchestrator)
    for agent in agents:
        if agent["name"].lower() == agent_name.lower():
            return agent
    return {"error": "Agent not found"}
