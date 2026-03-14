"""Attack Simulator REST endpoint."""

import random
import uuid
from datetime import datetime
from fastapi import APIRouter, Request
from models.schemas import SimulateAttackRequest, AttackType
from database.repository import save_attack
from websocket.manager import manager as ws_manager

router = APIRouter()

# Random IP pool for simulations
IP_POOL = [
    "192.168.1." + str(i) for i in range(1, 50)
] + [
    "10.0.0." + str(i) for i in range(1, 30)
] + [
    "203.0.113." + str(i) for i in range(1, 20)
]


@router.post("")
async def simulate_attack(payload: SimulateAttackRequest, request: Request):
    orchestrator = request.app.state.orchestrator
    source_ip = payload.source_ip or random.choice(IP_POOL)

    # Persist attack record
    attack = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "attack_type": payload.attack_type.value,
        "source_ip": source_ip,
        "target": "192.168.0.1",
        "intensity": payload.intensity,
        "detected": True,
        "mitigated": False,
    }
    await save_attack(attack)

    # Broadcast to WS clients
    await ws_manager.broadcast({
        "type": "simulation_started",
        "data": attack,
        "timestamp": datetime.utcnow().isoformat(),
    })

    # Trigger agent pipeline
    result = await orchestrator.trigger_simulation(
        payload.attack_type.value, source_ip, payload.intensity or "medium"
    )

    attack["mitigated"] = True
    return {
        "message": f"Attack simulation triggered: {payload.attack_type.value}",
        "attack": attack,
        "agent_result": result,
    }


@router.get("/attack-types")
async def list_attack_types():
    return {
        "attack_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in AttackType
        ]
    }
