"""Alerts REST endpoints."""

import csv
import io
from datetime import datetime, timedelta
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import Response
from typing import Optional
from database.repository import get_alerts, get_threat_level, count_documents, fetch_recent, fetch_one

router = APIRouter()


def _response_priority(response: dict) -> tuple[int, int, str]:
    action = str(response.get("action", "") or "")
    has_recommendations = bool(response.get("recommendations"))
    is_auto_resolve = action.startswith("Auto-resolve")
    timestamp = str(response.get("timestamp", "") or "")
    return (0 if has_recommendations else 1, 0 if not is_auto_resolve else 1, timestamp)


def _pick_best_response(responses: list[dict]) -> Optional[dict]:
    if not responses:
        return None
    return min(responses, key=_response_priority)


async def _find_incident_commander_response(alert: dict) -> Optional[dict]:
    direct_responses = await fetch_recent("responses", limit=50, query={"related_alert_id": alert.get("id")})
    best_direct = _pick_best_response(direct_responses)
    if best_direct:
        return best_direct

    details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
    linked_alert_id = details.get("related_alert_id") or details.get("parent_alert_id")
    if linked_alert_id:
        linked_responses = await fetch_recent("responses", limit=50, query={"related_alert_id": linked_alert_id})
        best_linked = _pick_best_response(linked_responses)
        if best_linked:
            return best_linked

    source_ip = alert.get("source_ip")
    threat_type = alert.get("threat_type")
    timestamp = alert.get("timestamp")

    if not source_ip or not threat_type or not isinstance(timestamp, str):
        return None

    try:
        center = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except Exception:
        return None

    sibling_alerts = await fetch_recent(
        "alerts",
        limit=50,
        query={
            "source_ip": source_ip,
            "threat_type": threat_type,
            "timestamp": {
                "$gte": (center - timedelta(minutes=5)).isoformat(),
                "$lte": (center + timedelta(minutes=5)).isoformat(),
            },
        },
    )
    sibling_ids = [item.get("id") for item in sibling_alerts if item.get("id")]
    if not sibling_ids:
        return None

    sibling_responses = await fetch_recent(
        "responses",
        limit=100,
        query={"related_alert_id": {"$in": sibling_ids}},
    )
    return _pick_best_response(sibling_responses)

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
    unresolved_statuses = ["active", "investigating", "blocked", "monitoring"]
    unresolved_query = {"status": {"$in": unresolved_statuses}}

    active = await count_documents("alerts", unresolved_query)
    critical = await count_documents("alerts", {**unresolved_query, "severity": "critical"})
    high = await count_documents("alerts", {**unresolved_query, "severity": "high"})
    medium = await count_documents("alerts", {**unresolved_query, "severity": "medium"})
    return {
        "total": total,
        "active": active,
        "critical": critical,
        "high": high,
        "medium": medium,
        "resolved": total - active,
    }


def _safe_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value)


@router.get("/report.csv")
async def download_alert_report_csv(
    start_time: str = Query(..., description="ISO timestamp inclusive start"),
    end_time: str = Query(..., description="ISO timestamp inclusive end"),
    severity: Optional[str] = Query(None),
    threat_types: Optional[str] = Query(None, description="Comma-separated threat types"),
):
    """Generate a CSV report of alerts for the selected period."""
    try:
        start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid start_time or end_time format")

    if start_dt > end_dt:
        raise HTTPException(status_code=400, detail="start_time must be <= end_time")

    alert_query = {
        "timestamp": {
            "$gte": start_dt.isoformat(),
            "$lte": end_dt.isoformat(),
        }
    }
    if severity:
        alert_query["severity"] = severity

    selected_threat_types: list[str] = []
    if threat_types:
        selected_threat_types = [item.strip() for item in threat_types.split(",") if item and item.strip()]
        if selected_threat_types:
            alert_query["threat_type"] = {"$in": selected_threat_types}

    alerts = await fetch_recent("alerts", limit=5000, query=alert_query)
    alert_ids = [a.get("id") for a in alerts if a.get("id")]

    responses_by_id: dict[str, list[dict]] = {}
    if alert_ids:
        responses = await fetch_recent(
            "responses",
            limit=10000,
            query={"related_alert_id": {"$in": alert_ids}},
        )
        for response in responses:
            related_id = response.get("related_alert_id")
            if not related_id:
                continue
            responses_by_id.setdefault(related_id, []).append(response)

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "timestamp",
        "alert_id",
        "agent",
        "event",
        "threat_type",
        "severity",
        "status",
        "source_ip",
        "target",
        "confidence",
        "commander_action",
        "commander_status",
        "commander_confidence",
        "commander_reasoning",
        "recommendations",
        "signals",
    ])

    for alert in alerts:
        response = _pick_best_response(responses_by_id.get(alert.get("id", ""), []))
        if response is None:
            response = await _find_incident_commander_response(alert)
        recommendations = response.get("recommendations") if response else []
        signals = response.get("signals") if response else []

        writer.writerow([
            _safe_text(alert.get("timestamp")),
            _safe_text(alert.get("id")),
            _safe_text(alert.get("agent")),
            _safe_text(alert.get("event")),
            _safe_text(alert.get("threat_type")),
            _safe_text(alert.get("severity")),
            _safe_text(alert.get("status")),
            _safe_text(alert.get("source_ip")),
            _safe_text(alert.get("target")),
            _safe_text(alert.get("confidence")),
            _safe_text(response.get("action") if response else ""),
            _safe_text(response.get("status") if response else ""),
            _safe_text(response.get("confidence") if response else ""),
            _safe_text(response.get("reasoning") if response else ""),
            " | ".join([_safe_text(item) for item in (recommendations or [])]),
            " | ".join([_safe_text(item) for item in (signals or [])]),
        ])

    csv_content = out.getvalue()
    out.close()

    filename = f"threat_alerts_report_{start_dt.strftime('%Y%m%d_%H%M')}_to_{end_dt.strftime('%Y%m%d_%H%M')}.csv"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=csv_content, media_type="text/csv", headers=headers)


@router.get("/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Return a single alert with its related commander response and recommendations."""
    alert = await fetch_one("alerts", {"id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    response = await _find_incident_commander_response(alert)

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
