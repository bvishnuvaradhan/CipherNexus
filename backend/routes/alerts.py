"""Alerts REST endpoints."""

from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from database.repository import get_alerts, get_threat_level, count_documents, fetch_recent

router = APIRouter()

# Recommendations by threat type
THREAT_RECOMMENDATIONS = {
    "brute_force": [
        "Enable account lockout after 5 failed attempts",
        "Implement multi-factor authentication",
        "Deploy rate limiting on authentication endpoints",
        "Review and rotate compromised credentials",
    ],
    "port_scan": [
        "Review and minimize exposed services",
        "Update firewall ACLs",
        "Enable port scan detection alerts",
    ],
    "sql_injection": [
        "Enable parameterized queries",
        "Deploy WAF rules",
        "Audit input validation",
        "Review database permissions",
    ],
    "xss": [
        "Implement Content Security Policy",
        "Sanitize all user inputs",
        "Enable HttpOnly cookies",
    ],
    "ransomware": [
        "Isolate infected hosts immediately",
        "Initiate backup restoration",
        "Preserve forensic evidence",
        "Notify incident response team",
    ],
    "ddos": [
        "Enable DDoS mitigation service",
        "Implement rate limiting at edge",
        "Scale infrastructure capacity",
    ],
    "data_exfiltration": [
        "Block outbound to suspicious destinations",
        "Enable DLP monitoring",
        "Review user access permissions",
    ],
    "mitm": [
        "Force HSTS on all endpoints",
        "Validate certificate chains",
        "Review ARP tables",
    ],
    "dns_spoofing": [
        "Enable DNSSEC",
        "Flush DNS caches",
        "Monitor DNS query logs",
    ],
    "command_control": [
        "Block C2 IPs at firewall",
        "Run endpoint forensic scan",
        "Review scheduled tasks",
    ],
    "suspicious_login": [
        "Force password reset",
        "Verify user identity",
        "Review account activity",
    ],
    "traffic_spike": [
        "Enable rate limiting",
        "Scale infrastructure",
        "Monitor for DDoS escalation",
    ],
}


@router.get("/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Return a single alert with its related commander response and recommendations."""
    # Find the alert
    alerts = await fetch_recent("alerts", limit=500)
    alert = next((a for a in alerts if a.get("id") == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Find related commander response
    responses = await fetch_recent("responses", limit=200)
    response = next((r for r in responses if r.get("related_alert_id") == alert_id), None)

    # Generate recommendations
    threat_type = alert.get("threat_type", "")
    severity = alert.get("severity", "medium")
    recs = THREAT_RECOMMENDATIONS.get(threat_type, ["Investigate source IP", "Review security logs"])
    if severity == "critical":
        recs = ["CRITICAL: Isolate affected systems immediately"] + recs

    return {
        "alert": alert,
        "commander_response": response,
        "recommendations": recs,
    }


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
