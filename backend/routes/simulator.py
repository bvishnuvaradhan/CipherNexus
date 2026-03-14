"""Attack Simulator REST endpoint."""

import random
import uuid
from datetime import datetime
from fastapi import APIRouter, Request
from models.schemas import SimulateAttackRequest, AttackType
from database.repository import save_attack, save_alert
from websocket.manager import manager as ws_manager
from ml.predictor import predict_anomaly

router = APIRouter()


def _severity_from_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def _build_flow_features(attack_type: str, intensity: str, attack: dict) -> dict:
    intensity_scale = {"low": 1.0, "medium": 1.8, "high": 2.6}
    scale = intensity_scale.get(intensity or "medium", 1.8)

    base = {
        "Destination Port": 80,
        "Flow Duration": int(1200 * scale),
        "Total Fwd Packets": int(12 * scale),
        "Total Backward Packets": int(8 * scale),
        "Flow Bytes/s": int(25000 * scale),
        "Flow Packets/s": round(16 * scale, 2),
    }

    if attack_type == AttackType.PORT_SCAN.value:
        base.update({"Destination Port": 22, "Flow Packets/s": round(35 * scale, 2)})
    elif attack_type == AttackType.BRUTE_FORCE.value:
        base.update({"Destination Port": 22, "Flow Duration": int(2000 * scale)})
    elif attack_type == AttackType.DATA_EXFILTRATION.value:
        base.update({"Destination Port": 443, "Flow Bytes/s": int(85000 * scale)})
    elif attack_type == AttackType.TRAFFIC_SPIKE.value:
        base.update({"Flow Packets/s": round(55 * scale, 2), "Total Fwd Packets": int(25 * scale)})
    elif attack_type == AttackType.SUSPICIOUS_LOGIN.value:
        base.update({"Destination Port": 3389, "Flow Duration": int(1600 * scale)})

    if attack.get("target"):
        base["Fwd Header Length"] = 20
    return base

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

    ml_result = None
    ml_alert = None
    try:
        flow_features = _build_flow_features(payload.attack_type.value, payload.intensity or "medium", attack)
        ml_result = predict_anomaly(flow_features)
        if ml_result.get("anomaly"):
            score = float(ml_result.get("score", 0.0))
            ml_alert = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat(),
                "agent": "System",
                "event": "ML Anomaly Detected (Simulation)",
                "threat_type": payload.attack_type.value,
                "severity": _severity_from_score(score),
                "source_ip": source_ip,
                "target": attack.get("target"),
                "status": "active",
                "confidence": round(score, 3),
                "details": {
                    "ml_prediction": ml_result,
                    "flow_features": flow_features,
                    "origin": "simulate_attack",
                },
            }
            await save_alert(ml_alert)
            await ws_manager.broadcast_alert(ml_alert)
    except FileNotFoundError:
        # Model optional: simulation works even if artifacts are not available yet.
        ml_result = {"prediction": "unavailable", "reason": "model_not_trained"}
    except Exception as e:
        ml_result = {"prediction": "error", "reason": str(e)}

    attack["mitigated"] = True
    return {
        "message": f"Attack simulation triggered: {payload.attack_type.value}",
        "attack": attack,
        "agent_result": result,
        "ml_result": ml_result,
        "ml_alert": ml_alert,
    }


@router.get("/attack-types")
async def list_attack_types():
    return {
        "attack_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in AttackType
        ]
    }
