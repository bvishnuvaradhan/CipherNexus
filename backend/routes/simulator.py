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
    "203.0.113." + str(i) for i in range(1, 50)
] + [
    "198.51.100." + str(i) for i in range(1, 30)
] + [
    "185.220." + str(i) + "." + str(j) for i in range(100, 103) for j in range(1, 10)
]

ATTACK_LABELS = {
    "brute_force":      "Brute Force Attack",
    "port_scan":        "Port Scan",
    "suspicious_login": "Suspicious Login",
    "data_exfiltration":"Data Exfiltration",
    "traffic_spike":    "Traffic Spike",
    "malware":          "Malware Injection",
    "ddos":             "DDoS Attack",
    "sql_injection":    "SQL Injection",
    "xss":              "Cross-Site Scripting (XSS)",
    "ransomware":       "Ransomware Deployment",
    "mitm":             "Man-in-the-Middle Attack",
    "dns_spoofing":     "DNS Spoofing",
    "command_control":  "Command & Control (C2) Beacon",
}


@router.post("")
async def simulate_attack(payload: SimulateAttackRequest, request: Request):
    orchestrator = request.app.state.orchestrator
    source_ip = payload.source_ip or random.choice(IP_POOL)
    target = payload.target_ip or "192.168.0.1"

    # Build parameter map from payload
    params = {
        k: v for k, v in {
            "username":         payload.username,
            "attempt_count":    payload.attempt_count,
            "auth_protocol":    payload.auth_protocol,
            "password_list":    payload.password_list,
            "port_range_start": payload.port_range_start,
            "port_range_end":   payload.port_range_end,
            "scan_technique":   payload.scan_technique,
            "scan_timing":      payload.scan_timing,
            "device_fingerprint": payload.device_fingerprint,
            "payload_size_mb":  payload.payload_size_mb,
            "exfil_protocol":   payload.exfil_protocol,
            "destination_type": payload.destination_type,
            "exfil_encryption": payload.exfil_encryption,
            "packet_rate":      payload.packet_rate,
            "flood_type":       payload.flood_type,
            "botnet_size":      payload.botnet_size,
            "spike_protocol":   payload.spike_protocol,
            "source_spoofing":  payload.source_spoofing,
            "injection_type":   payload.injection_type,
            "target_endpoint":  payload.target_endpoint,
            "waf_evasion":      payload.waf_evasion,
            "database_type":    payload.database_type,
            "xss_type":         payload.xss_type,
            "payload_encoding": payload.payload_encoding,
            "spread_rate":      payload.spread_rate,
            "encryption_algo":  payload.encryption_algo,
            "ransom_family":    payload.ransom_family,
            "target_protocol":  payload.target_protocol,
            "mitm_technique":   payload.mitm_technique,
            "capture_type":     payload.capture_type,
            "target_domain":    payload.target_domain,
            "redirect_target":  payload.redirect_target,
            "record_type":      payload.record_type,
            "beacon_interval":  payload.beacon_interval,
            "c2_protocol":      payload.c2_protocol,
            "persistence_method": payload.persistence_method,
            "jitter_percent":   payload.jitter_percent,
            "duration_seconds": payload.duration_seconds,
        }.items() if v is not None
    }

    # Persist attack record
    attack = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "attack_type": payload.attack_type.value,
        "attack_label": ATTACK_LABELS.get(payload.attack_type.value, payload.attack_type.value),
        "source_ip": source_ip,
        "target": target,
        "intensity": payload.intensity,
        "parameters": params,
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

    # Trigger agent pipeline with full params
    result = await orchestrator.trigger_simulation(
        payload.attack_type.value,
        source_ip,
        payload.intensity or "medium",
        target=target,
        params=params,
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
        "message": f"Attack simulation triggered: {ATTACK_LABELS.get(payload.attack_type.value, payload.attack_type.value)}",
        "attack": attack,
        "agent_result": result,
        "ml_result": ml_result,
        "ml_alert": ml_alert,
    }


@router.get("/attack-types")
async def list_attack_types():
    return {
        "attack_types": [
            {
                "value": t.value,
                "label": ATTACK_LABELS.get(t.value, t.value.replace("_", " ").title()),
            }
            for t in AttackType
        ]
    }
