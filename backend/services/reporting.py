import csv
import io
from datetime import datetime, timedelta
from typing import Optional

from database.repository import fetch_recent


def parse_iso_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def safe_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value)


def response_priority(response: dict) -> tuple[int, int, str]:
    action = str(response.get("action", "") or "")
    has_recommendations = bool(response.get("recommendations"))
    is_auto_resolve = action.startswith("Auto-resolve")
    timestamp = str(response.get("timestamp", "") or "")
    return (0 if has_recommendations else 1, 0 if not is_auto_resolve else 1, timestamp)


def pick_best_response(responses: list[dict]) -> Optional[dict]:
    if not responses:
        return None
    return min(responses, key=response_priority)


async def find_incident_commander_response(alert: dict) -> Optional[dict]:
    direct_responses = await fetch_recent("responses", limit=50, query={"related_alert_id": alert.get("id")})
    best_direct = pick_best_response(direct_responses)
    if best_direct:
        return best_direct

    details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
    linked_alert_id = details.get("related_alert_id") or details.get("parent_alert_id")
    if linked_alert_id:
        linked_responses = await fetch_recent("responses", limit=50, query={"related_alert_id": linked_alert_id})
        best_linked = pick_best_response(linked_responses)
        if best_linked:
            return best_linked

    source_ip = alert.get("source_ip")
    threat_type = alert.get("threat_type")
    timestamp = alert.get("timestamp")

    if not source_ip or not threat_type or not isinstance(timestamp, str):
        return None

    try:
        center = parse_iso_datetime(timestamp)
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
    return pick_best_response(sibling_responses)


async def build_report_csv_content(
    start_dt: datetime,
    end_dt: datetime,
    severity: Optional[str] = None,
    threat_types: Optional[list[str]] = None,
) -> tuple[str, int]:
    alert_query = {
        "timestamp": {
            "$gte": start_dt.isoformat(),
            "$lte": end_dt.isoformat(),
        }
    }
    if severity:
        alert_query["severity"] = severity
    if threat_types:
        alert_query["threat_type"] = {"$in": threat_types}

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
        response = pick_best_response(responses_by_id.get(alert.get("id", ""), []))
        if response is None:
            response = await find_incident_commander_response(alert)
        recommendations = response.get("recommendations") if response else []
        signals = response.get("signals") if response else []

        writer.writerow([
            safe_text(alert.get("timestamp")),
            safe_text(alert.get("id")),
            safe_text(alert.get("agent")),
            safe_text(alert.get("event")),
            safe_text(alert.get("threat_type")),
            safe_text(alert.get("severity")),
            safe_text(alert.get("status")),
            safe_text(alert.get("source_ip")),
            safe_text(alert.get("target")),
            safe_text(alert.get("confidence")),
            safe_text(response.get("action") if response else ""),
            safe_text(response.get("status") if response else ""),
            safe_text(response.get("confidence") if response else ""),
            safe_text(response.get("reasoning") if response else ""),
            " | ".join([safe_text(item) for item in (recommendations or [])]),
            " | ".join([safe_text(item) for item in (signals or [])]),
        ])

    csv_content = out.getvalue()
    out.close()
    return csv_content, len(alerts)
