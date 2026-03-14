"""Repository layer — strict MongoDB-backed data access."""

from __future__ import annotations
import copy
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from bson import ObjectId

from database.connection import get_db


def _col(name: str):
    db = get_db()
    if db is None:
        raise RuntimeError("MongoDB is not connected")
    return db[name]


def _serialize_doc(doc: Dict) -> Dict:
    """Convert ObjectIds and other non-JSON-serializable types to strings."""
    if doc is None:
        return None
    result = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

async def insert_document(collection: str, document: Dict) -> str:
    col = _col(collection)
    # pymongo may inject `_id` into the passed dict; keep caller payload immutable.
    payload = copy.deepcopy(document)
    result = await col.insert_one(payload)
    return str(result.inserted_id)


async def fetch_recent(
    collection: str,
    limit: int = 50,
    query: Optional[Dict] = None,
    sort_field: str = "timestamp",
) -> List[Dict]:
    q = query or {}
    col = _col(collection)
    cursor = col.find(q).sort(sort_field, -1).limit(limit)
    docs = await cursor.to_list(length=limit)

    return [_serialize_doc(doc) for doc in docs]


async def count_documents(collection: str, query: Optional[Dict] = None) -> int:
    q = query or {}
    col = _col(collection)
    return await col.count_documents(q)


async def update_document(collection: str, query: Dict, update: Dict) -> None:
    col = _col(collection)
    await col.update_one(query, update)


async def fetch_one(collection: str, query: Dict, sort_field: Optional[str] = None) -> Optional[Dict]:
    col = _col(collection)
    if sort_field:
        doc = await col.find(query).sort(sort_field, -1).limit(1).to_list(length=1)
        return _serialize_doc(doc[0]) if doc else None
    doc = await col.find_one(query)
    return _serialize_doc(doc) if doc else None


async def upsert_document(collection: str, query: Dict, update: Dict) -> None:
    col = _col(collection)
    await col.update_one(query, update, upsert=True)


async def clear_collections(collections: Optional[List[str]] = None) -> Dict[str, int]:
    """Delete all documents from selected collections."""
    names = collections or ["alerts", "logs", "agent_messages", "responses", "attacks"]
    result: Dict[str, int] = {}
    db = get_db()
    if db is None:
        raise RuntimeError("MongoDB is not connected")

    for name in names:
        try:
            delete_result = await db[name].delete_many({})
            result[name] = int(delete_result.deleted_count)
        except Exception as e:
            print(f"[WARN] Failed to clear collection '{name}': {e}")
            result[name] = -1

    return result


# ---------------------------------------------------------------------------
# Domain-specific helpers
# ---------------------------------------------------------------------------

async def save_alert(alert_dict: Dict) -> str:
    return await insert_document("alerts", alert_dict)


async def save_log(log_dict: Dict) -> str:
    return await insert_document("logs", log_dict)


async def save_agent_message(msg_dict: Dict) -> str:
    return await insert_document("agent_messages", msg_dict)


async def save_response(resp_dict: Dict) -> str:
    return await insert_document("responses", resp_dict)


async def save_attack(attack_dict: Dict) -> str:
    return await insert_document("attacks", attack_dict)


async def get_alerts(limit: int = 50, severity: Optional[str] = None) -> List[Dict]:
    query = {}
    if severity:
        query["severity"] = severity
    return await fetch_recent("alerts", limit=limit, query=query)


async def get_logs(limit: int = 100) -> List[Dict]:
    return await fetch_recent("logs", limit=limit)


async def get_logs_for_alert(alert_id: str, limit: int = 200) -> Dict[str, Any]:
    """Fetch contextual logs for a specific alert."""
    alert = await fetch_one("alerts", {"id": alert_id})
    if not alert:
        return {"alert": None, "logs": []}

    query: Dict[str, Any] = {}
    source_ip = alert.get("source_ip")
    if source_ip:
        query["source_ip"] = source_ip

    ts_raw = alert.get("timestamp")
    if isinstance(ts_raw, str):
        try:
            alert_dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            since = (alert_dt - timedelta(minutes=5)).isoformat()
            query["timestamp"] = {"$gte": since}
        except Exception:
            pass

    logs = await fetch_recent("logs", limit=limit, query=query)
    return {"alert": alert, "logs": logs}


async def get_agent_messages(limit: int = 50) -> List[Dict]:
    return await fetch_recent("agent_messages", limit=limit)


async def get_responses(limit: int = 50) -> List[Dict]:
    return await fetch_recent("responses", limit=limit)


async def get_active_alert_count() -> int:
    return await count_documents("alerts", {"status": "active"})


async def update_alert_status(alert_id: str, status: str, extra_details: Optional[Dict[str, Any]] = None) -> Optional[Dict]:
    """Update alert status and return the updated alert document."""
    col = _col("alerts")
    details = extra_details or {}
    update_payload: Dict[str, Any] = {
        "status": status,
        "updated_at": datetime.utcnow().isoformat(),
    }
    if details:
        update_payload["lifecycle"] = details

    await col.update_one({"id": alert_id}, {"$set": update_payload})
    return await fetch_one("alerts", {"id": alert_id})


async def update_incident_alerts_status(
    alert_id: str,
    status: str,
    extra_details: Optional[Dict[str, Any]] = None,
    window_minutes: int = 5,
) -> Dict[str, Any]:
    """Update all alerts that appear to belong to the same incident as the given alert."""
    primary = await fetch_one("alerts", {"id": alert_id})
    if not primary:
        return {"alert": None, "updated": 0}

    source_ip = primary.get("source_ip")
    threat_type = primary.get("threat_type")
    timestamp = primary.get("timestamp")

    details = extra_details or {}
    update_payload: Dict[str, Any] = {
        "status": status,
        "updated_at": datetime.utcnow().isoformat(),
    }
    if details:
        update_payload["lifecycle"] = details

    query: Dict[str, Any] = {
        "status": {"$in": ["active", "investigating", "blocked", "monitoring"]},
    }
    if source_ip:
        query["source_ip"] = source_ip
    if threat_type:
        query["threat_type"] = threat_type

    if isinstance(timestamp, str):
        try:
            center = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            query["timestamp"] = {
                "$gte": (center - timedelta(minutes=window_minutes)).isoformat(),
                "$lte": (center + timedelta(minutes=window_minutes)).isoformat(),
            }
        except Exception:
            pass

    col = _col("alerts")
    result = await col.update_many(query, {"$set": update_payload})
    updated_primary = await fetch_one("alerts", {"id": alert_id})
    return {"alert": updated_primary, "updated": int(result.modified_count)}


async def has_recent_incident_activity(
    alert_id: str,
    since_iso: str,
    statuses: Optional[List[str]] = None,
    window_minutes: int = 5,
) -> bool:
    """Check whether the same incident cluster has newer unresolved activity since a cutoff time."""
    primary = await fetch_one("alerts", {"id": alert_id})
    if not primary:
        return False

    source_ip = primary.get("source_ip")
    threat_type = primary.get("threat_type")
    timestamp = primary.get("timestamp")

    query: Dict[str, Any] = {
        "status": {"$in": statuses or ["active", "investigating", "blocked", "monitoring"]},
        "timestamp": {"$gte": since_iso},
    }
    if source_ip:
        query["source_ip"] = source_ip
    if threat_type:
        query["threat_type"] = threat_type

    if isinstance(timestamp, str):
        try:
            center = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            query["timestamp"]["$lte"] = (center + timedelta(minutes=window_minutes)).isoformat()
        except Exception:
            pass

    return await count_documents("alerts", query) > 0


async def mark_attacks_mitigated(source_ip: str, details: Optional[Dict[str, Any]] = None) -> int:
    """Mark non-mitigated attack simulation records as mitigated for a source IP."""
    col = _col("attacks")
    payload = {
        "mitigated": True,
        "mitigated_at": datetime.utcnow().isoformat(),
    }
    if details:
        payload["mitigation_details"] = details
    result = await col.update_many({"source_ip": source_ip, "mitigated": {"$ne": True}}, {"$set": payload})
    return int(result.modified_count)


async def resolve_monitoring_responses_for_alert(alert_id: str, details: Optional[Dict[str, Any]] = None) -> int:
    """Mark monitoring responses as resolved for one alert id."""
    col = _col("responses")
    payload: Dict[str, Any] = {
        "status": "resolved",
        "resolved_at": datetime.utcnow().isoformat(),
    }
    if details:
        payload["resolution_details"] = details
    result = await col.update_many(
        {"related_alert_id": alert_id, "status": "monitoring"},
        {"$set": payload},
    )
    return int(result.modified_count)


async def get_due_monitoring_responses(cutoff_iso: str, limit: int = 100) -> List[Dict]:
    """Return monitoring responses older than cutoff timestamp."""
    query = {
        "status": "monitoring",
        "timestamp": {"$lte": cutoff_iso},
    }
    return await fetch_recent("responses", limit=limit, query=query)


async def get_due_blocked_responses(cutoff_iso: str, limit: int = 100) -> List[Dict]:
    """Return blocked responses older than cutoff timestamp."""
    query = {
        "status": "blocked",
        "timestamp": {"$lte": cutoff_iso},
    }
    return await fetch_recent("responses", limit=limit, query=query)


async def resolve_blocked_responses_for_alert(alert_id: str, details: Optional[Dict[str, Any]] = None) -> int:
    """Mark blocked responses as resolved for one alert id."""
    col = _col("responses")
    payload: Dict[str, Any] = {
        "status": "resolved",
        "resolved_at": datetime.utcnow().isoformat(),
    }
    if details:
        payload["resolution_details"] = details
    result = await col.update_many(
        {"related_alert_id": alert_id, "status": "blocked"},
        {"$set": payload},
    )
    return int(result.modified_count)


async def get_threat_level() -> Dict[str, Any]:
    """Compute overall threat level from unresolved alerts."""
    unresolved_statuses = ["active", "investigating", "blocked", "monitoring"]
    unresolved_query = {"status": {"$in": unresolved_statuses}}

    critical = await count_documents("alerts", {**unresolved_query, "severity": "critical"})
    high = await count_documents("alerts", {**unresolved_query, "severity": "high"})
    medium = await count_documents("alerts", {**unresolved_query, "severity": "medium"})
    total_active = await count_documents("alerts", unresolved_query)

    score = min(100, critical * 25 + high * 10 + medium * 4)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "level": level,
        "score": score,
        "active_alerts": total_active,
        "critical": critical,
        "high": high,
        "medium": medium,
    }


async def _avg_and_count_numeric(collection: str, match: Dict[str, Any], field: str) -> tuple[float, int]:
    """Return average and count for a numeric field in a collection."""
    col = _col(collection)
    match_query = {**match, field: {"$type": "number"}}
    pipeline = [
        {"$match": match_query},
        {"$group": {"_id": None, "avg": {"$avg": f"${field}"}, "count": {"$sum": 1}}},
    ]
    docs = await col.aggregate(pipeline).to_list(length=1)
    if not docs:
        return 0.0, 0
    row = docs[0]
    return float(row.get("avg", 0.0) or 0.0), int(row.get("count", 0) or 0)


async def get_agent_activity_metrics(agent_name: str) -> Dict[str, Any]:
    """Compute persisted activity metrics for an agent from MongoDB."""
    unresolved_alert_statuses = ["active", "investigating", "blocked", "monitoring"]
    unresolved_response_statuses = ["blocked", "monitoring"]

    current_alerts_count = await count_documents(
        "alerts",
        {"agent": agent_name, "status": {"$in": unresolved_alert_statuses}},
    )
    current_responses_count = await count_documents(
        "responses",
        {"agent": agent_name, "status": {"$in": unresolved_response_statuses}},
    )

    total_alerts_count = await count_documents("alerts", {"agent": agent_name})
    total_responses_count = await count_documents("responses", {"agent": agent_name})

    alert_avg, alert_n = await _avg_and_count_numeric("alerts", {"agent": agent_name}, "confidence")
    response_avg, response_n = await _avg_and_count_numeric("responses", {"agent": agent_name}, "confidence")

    runtime_metric = await fetch_one("agent_runtime_metrics", {"name": agent_name}) or {}

    total_n = alert_n + response_n
    if total_n > 0:
        weighted_avg = (
            (alert_avg * alert_n)
            + (response_avg * response_n)
        ) / total_n
    else:
        weighted_avg = 0.0

    current_threat_count = int(current_alerts_count + current_responses_count)
    historical_total = int(total_alerts_count + total_responses_count)
    runtime_total = int(runtime_metric.get("total_threats_detected", runtime_metric.get("threat_count", 0)) or 0)
    confidence_avg = max(
        round(float(weighted_avg), 3),
        round(float(runtime_metric.get("confidence_avg", 0.0) or 0.0), 3),
    )

    return {
        "threat_count": current_threat_count,
        "total_threats_detected": max(current_threat_count, historical_total, runtime_total),
        "confidence_avg": confidence_avg,
        "uptime_seconds": int(runtime_metric.get("uptime_seconds", 0) or 0),
        "last_action": runtime_metric.get("last_action"),
        "last_action_time": runtime_metric.get("last_action_time"),
    }


async def persist_agent_runtime_metrics(status: Dict[str, Any]) -> None:
    """Persist monotonic agent runtime metrics so agent cards survive process and page reloads."""
    name = status.get("name")
    if not name:
        return

    existing = await fetch_one("agent_runtime_metrics", {"name": name}) or {}

    payload = {
        "name": name,
        "role": status.get("role"),
        "responsibilities": status.get("responsibilities", []),
        "status": status.get("status", existing.get("status", "offline")),
        "threat_count": max(int(existing.get("threat_count", 0) or 0), int(status.get("threat_count", 0) or 0)),
        "total_threats_detected": max(
            int(existing.get("total_threats_detected", 0) or 0),
            int(existing.get("threat_count", 0) or 0),
            int(status.get("threat_count", 0) or 0),
        ),
        "confidence_avg": max(
            float(existing.get("confidence_avg", 0.0) or 0.0),
            float(status.get("confidence_avg", 0.0) or 0.0),
        ),
        "uptime_seconds": max(
            int(existing.get("uptime_seconds", 0) or 0),
            int(status.get("uptime_seconds", 0) or 0),
        ),
        "last_action": status.get("last_action") or existing.get("last_action"),
        "last_action_time": status.get("last_action_time") or existing.get("last_action_time"),
        "updated_at": datetime.utcnow().isoformat(),
    }

    await upsert_document(
        "agent_runtime_metrics",
        {"name": name},
        {"$set": payload},
    )
