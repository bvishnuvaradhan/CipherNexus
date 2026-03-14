"""Agent status REST endpoints."""

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("")
async def list_agents(request: Request):
    orchestrator = request.app.state.orchestrator
    statuses = orchestrator.get_all_agent_statuses()
    return {"agents": statuses}


@router.get("/{agent_name}")
async def get_agent(agent_name: str, request: Request):
    orchestrator = request.app.state.orchestrator
    statuses = orchestrator.get_all_agent_statuses()
    for agent in statuses:
        if agent["name"].lower() == agent_name.lower():
            return agent
    return {"error": "Agent not found"}
