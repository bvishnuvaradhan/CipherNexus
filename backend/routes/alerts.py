"""Alerts REST endpoints."""

from datetime import datetime, timedelta
from uuid import uuid4
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import Literal, Optional
from database.repository import (
    count_documents,
    fetch_one,
    fetch_recent,
    get_alerts,
    get_threat_level,
    insert_document,
    update_document,
)
from services.reporting import build_report_csv_content, find_incident_commander_response, parse_iso_datetime
from services.report_scheduler import materialize_scheduled_report

router = APIRouter()


FREQUENCY_TO_DELTA = {
    "hourly": timedelta(hours=1),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
}


class ReportScheduleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=64)
    frequency: Literal["hourly", "daily", "weekly"] = "daily"
    lookback_hours: int = Field(default=24, ge=1, le=24 * 14)
    severity: Optional[Literal["critical", "high", "medium", "low"]] = None
    threat_types: list[str] = Field(default_factory=list)

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


@router.get("/report.csv")
async def download_alert_report_csv(
    start_time: str = Query(..., description="ISO timestamp inclusive start"),
    end_time: str = Query(..., description="ISO timestamp inclusive end"),
    severity: Optional[str] = Query(None),
    threat_types: Optional[str] = Query(None, description="Comma-separated threat types"),
):
    """Generate a CSV report of alerts for the selected period."""
    try:
        start_dt = parse_iso_datetime(start_time)
        end_dt = parse_iso_datetime(end_time)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid start_time or end_time format")

    if start_dt > end_dt:
        raise HTTPException(status_code=400, detail="start_time must be <= end_time")

    selected_threat_types: list[str] = []
    if threat_types:
        selected_threat_types = [item.strip() for item in threat_types.split(",") if item and item.strip()]
    csv_content, _ = await build_report_csv_content(
        start_dt=start_dt,
        end_dt=end_dt,
        severity=severity,
        threat_types=selected_threat_types,
    )

    filename = f"threat_alerts_report_{start_dt.strftime('%Y%m%d_%H%M')}_to_{end_dt.strftime('%Y%m%d_%H%M')}.csv"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=csv_content, media_type="text/csv", headers=headers)


@router.get("/report-schedules")
async def list_report_schedules():
    schedules = await fetch_recent(
        "report_schedules",
        limit=200,
        query={"deleted": {"$ne": True}},
        sort_field="created_at",
    )
    return {"schedules": schedules, "total": len(schedules)}


@router.post("/report-schedules")
async def create_report_schedule(payload: ReportScheduleCreate):
    now = datetime.utcnow()
    schedule_id = str(uuid4())
    delta = FREQUENCY_TO_DELTA.get(payload.frequency, timedelta(days=1))
    sanitized_threat_types = sorted({item.strip() for item in payload.threat_types if item and item.strip()})

    doc = {
        "id": schedule_id,
        "name": payload.name,
        "frequency": payload.frequency,
        "lookback_hours": payload.lookback_hours,
        "severity": payload.severity,
        "threat_types": sanitized_threat_types,
        "enabled": True,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "last_run_at": None,
        "next_run_at": (now + delta).isoformat(),
    }
    await insert_document("report_schedules", doc)
    return {"ok": True, "schedule": doc}


@router.patch("/report-schedules/{schedule_id}")
async def update_report_schedule(schedule_id: str, enabled: Optional[bool] = Query(None)):
    existing = await fetch_one("report_schedules", {"id": schedule_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Report schedule not found")

    patch = {"updated_at": datetime.utcnow().isoformat()}
    if enabled is not None:
        patch["enabled"] = enabled
        if enabled:
            frequency = str(existing.get("frequency", "daily") or "daily").lower()
            patch["next_run_at"] = (datetime.utcnow() + FREQUENCY_TO_DELTA.get(frequency, timedelta(days=1))).isoformat()

    await update_document("report_schedules", {"id": schedule_id}, {"$set": patch})
    updated = await fetch_one("report_schedules", {"id": schedule_id})
    return {"ok": True, "schedule": updated}


@router.delete("/report-schedules/{schedule_id}")
async def delete_report_schedule(schedule_id: str):
    existing = await fetch_one("report_schedules", {"id": schedule_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Report schedule not found")

    await update_document(
        "report_schedules",
        {"id": schedule_id},
        {"$set": {"enabled": False, "deleted": True, "updated_at": datetime.utcnow().isoformat()}},
    )
    return {"ok": True}


@router.post("/report-schedules/{schedule_id}/run-now")
async def run_report_schedule_now(schedule_id: str):
    schedule = await fetch_one("report_schedules", {"id": schedule_id, "deleted": {"$ne": True}})
    if not schedule:
        raise HTTPException(status_code=404, detail="Report schedule not found")

    report_meta = await materialize_scheduled_report(schedule)
    return {"ok": True, "report": report_meta}


@router.get("/scheduled-reports")
async def list_scheduled_reports(schedule_id: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=200)):
    query = {"deleted": {"$ne": True}}
    if schedule_id:
        query["schedule_id"] = schedule_id
    reports = await fetch_recent("scheduled_reports", limit=limit, query=query, sort_field="generated_at")
    for report in reports:
        report.pop("csv_content", None)
    return {"reports": reports, "total": len(reports)}


@router.delete("/scheduled-reports/{report_id}")
async def delete_scheduled_report(report_id: str):
    report = await fetch_one("scheduled_reports", {"id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    await update_document(
        "scheduled_reports",
        {"id": report_id},
        {"$set": {"deleted": True, "updated_at": datetime.utcnow().isoformat()}},
    )
    return {"ok": True}


@router.get("/scheduled-reports/{report_id}/download")
async def download_scheduled_report(report_id: str):
    report = await fetch_one("scheduled_reports", {"id": report_id})
    if not report:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    csv_content = str(report.get("csv_content", ""))
    filename = str(report.get("filename") or f"scheduled_report_{report_id}.csv")
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=csv_content, media_type="text/csv", headers=headers)


@router.get("/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Return a single alert with its related commander response and recommendations."""
    alert = await fetch_one("alerts", {"id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    response = await find_incident_commander_response(alert)

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
