"""Utilities to populate MongoDB with realistic SOC sample data."""

from __future__ import annotations

from datetime import datetime, timedelta
from random import Random
from typing import Dict

from database.repository import insert_document


ALERT_PATTERNS = [
    ("Brute-force login attempts exceeded threshold", "brute_force", "high"),
    ("Unusual outbound transfer volume detected", "data_exfiltration", "critical"),
    ("Lateral movement pattern from workstation", "suspicious_login", "medium"),
    ("External host scanning internal ports", "port_scan", "high"),
    ("Web gateway packet-rate anomaly", "traffic_spike", "medium"),
]

LOG_PATTERNS = [
    ("login_failed", "Sentry", "high", "Multiple failed SSH logins from source host"),
    ("system_event", "System", "low", "IAM policy sync completed"),
    ("data_transfer", "Detective", "medium", "Large encrypted payload moved to external ASN"),
    ("firewall_block", "Commander", "high", "Firewall policy auto-block applied"),
    ("port_scan", "Sentry", "medium", "Horizontal scan pattern observed"),
]

RESPONSE_PATTERNS = [
    ("Block source IP at edge firewall", "blocked"),
    ("Enable deep packet inspection for segment", "monitoring"),
    ("Force password reset for impacted user", "resolved"),
    ("Isolate suspicious endpoint from VLAN", "blocked"),
]

AGENT_MESSAGE_PATTERNS = [
    ("Sentry", "Commander", "traffic_spike", "alert"),
    ("Detective", "Commander", "brute_force_detected", "alert"),
    ("Commander", "Detective", "verify_ip", "query"),
    ("Detective", "Commander", "ip_verification_result", "response"),
]


async def seed_real_data(
    *,
    alerts: int = 30,
    logs: int = 80,
    responses: int = 20,
    agent_messages: int = 40,
    attacks: int = 15,
    seed: int = 20260314,
) -> Dict[str, int]:
    """Insert realistic SOC sample records into persistence collections."""
    rng = Random(seed)
    now = datetime.utcnow()

    counters = {
        "alerts": 0,
        "logs": 0,
        "responses": 0,
        "agent_messages": 0,
        "attacks": 0,
    }

    for i in range(alerts):
        event, threat_type, severity = ALERT_PATTERNS[i % len(ALERT_PATTERNS)]
        ts = now - timedelta(minutes=i * rng.randint(2, 8))
        payload = {
            "timestamp": ts.isoformat(),
            "agent": "Detective" if i % 2 else "Sentry",
            "event": event,
            "threat_type": threat_type,
            "severity": severity,
            "source_ip": f"203.0.113.{rng.randint(1, 220)}",
            "target": rng.choice(["api-gateway", "db-primary", "vpn-edge", "auth-service"]),
            "status": rng.choice(["active", "investigating", "resolved", "blocked"]),
            "confidence": round(rng.uniform(0.66, 0.98), 2),
            "details": {
                "geo": rng.choice(["US", "DE", "SG", "IN", "BR"]),
                "asn": f"AS{rng.randint(1000, 65000)}",
                "source": "seeded_real_data",
            },
        }
        await insert_document("alerts", payload)
        counters["alerts"] += 1

    for i in range(logs):
        event_type, agent, severity, message = LOG_PATTERNS[i % len(LOG_PATTERNS)]
        ts = now - timedelta(minutes=i * rng.randint(1, 5))
        payload = {
            "timestamp": ts.isoformat(),
            "event_type": event_type,
            "agent": agent,
            "severity": severity,
            "message": message,
            "source_ip": f"198.51.100.{rng.randint(1, 220)}",
            "user": rng.choice(["admin", "analyst", "service-account", "root", "ops"]),
            "details": {
                "hostname": rng.choice(["k8s-node-1", "k8s-node-3", "jumpbox-2", "db-replica-1"]),
                "source": "seeded_real_data",
            },
        }
        await insert_document("logs", payload)
        counters["logs"] += 1

    for i in range(responses):
        action, status = RESPONSE_PATTERNS[i % len(RESPONSE_PATTERNS)]
        ts = now - timedelta(minutes=i * rng.randint(3, 10))
        payload = {
            "timestamp": ts.isoformat(),
            "action": action,
            "target": rng.choice(["edge-fw", "idm", "endpoint-agent", "vpn-gw"]),
            "agent": "Commander",
            "confidence": round(rng.uniform(0.72, 0.99), 2),
            "reasoning": "Automated triage confirmed correlated suspicious behavior across network and auth telemetry.",
            "status": status,
            "signals": [
                "Packet rate exceeded baseline",
                "Failed login burst detected",
                "Threat confidence above policy threshold",
            ],
        }
        await insert_document("responses", payload)
        counters["responses"] += 1

    for i in range(agent_messages):
        from_agent, to_agent, event, message_type = AGENT_MESSAGE_PATTERNS[i % len(AGENT_MESSAGE_PATTERNS)]
        ts = now - timedelta(minutes=i * rng.randint(1, 6))
        payload = {
            "timestamp": ts.isoformat(),
            "from_agent": from_agent,
            "to_agent": to_agent,
            "event": event,
            "ip": f"192.0.2.{rng.randint(1, 220)}",
            "severity": rng.choice(["medium", "high", "critical"]),
            "message_type": message_type,
            "payload": {
                "confidence": round(rng.uniform(0.6, 0.96), 2),
                "source": "seeded_real_data",
            },
        }
        await insert_document("agent_messages", payload)
        counters["agent_messages"] += 1

    attack_types = [
        "brute_force",
        "port_scan",
        "suspicious_login",
        "data_exfiltration",
        "traffic_spike",
    ]
    for i in range(attacks):
        ts = now - timedelta(minutes=i * rng.randint(4, 12))
        payload = {
            "timestamp": ts.isoformat(),
            "attack_type": attack_types[i % len(attack_types)],
            "source_ip": f"10.10.{rng.randint(0, 20)}.{rng.randint(1, 220)}",
            "target": rng.choice(["192.168.0.1", "172.16.0.5", "10.0.0.10"]),
            "intensity": rng.choice(["low", "medium", "high"]),
            "detected": True,
            "mitigated": rng.choice([True, False]),
        }
        await insert_document("attacks", payload)
        counters["attacks"] += 1

    return counters
