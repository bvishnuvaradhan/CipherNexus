"""Repository layer — strict MongoDB-backed data access."""

from __future__ import annotations
import copy
from datetime import datetime
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


async def get_agent_messages(limit: int = 50) -> List[Dict]:
    return await fetch_recent("agent_messages", limit=limit)


async def get_responses(limit: int = 50) -> List[Dict]:
    return await fetch_recent("responses", limit=limit)


async def get_active_alert_count() -> int:
    return await count_documents("alerts", {"status": "active"})


async def get_threat_level() -> Dict[str, Any]:
    """Compute overall threat level from active alerts."""
    critical = await count_documents("alerts", {"severity": "critical", "status": "active"})
    high = await count_documents("alerts", {"severity": "high", "status": "active"})
    medium = await count_documents("alerts", {"severity": "medium", "status": "active"})
    total_active = await count_documents("alerts", {"status": "active"})

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
    alerts_count = await count_documents("alerts", {"agent": agent_name})
    responses_count = await count_documents("responses", {"agent": agent_name})
    messages_count = await count_documents("agent_messages", {"from_agent": agent_name})

    alert_avg, alert_n = await _avg_and_count_numeric("alerts", {"agent": agent_name}, "confidence")
    response_avg, response_n = await _avg_and_count_numeric("responses", {"agent": agent_name}, "confidence")
    msg_avg, msg_n = await _avg_and_count_numeric("agent_messages", {"from_agent": agent_name}, "payload.confidence")

    total_n = alert_n + response_n + msg_n
    if total_n > 0:
        weighted_avg = (
            (alert_avg * alert_n)
            + (response_avg * response_n)
            + (msg_avg * msg_n)
        ) / total_n
    else:
        weighted_avg = 0.0

    return {
        "threat_count": int(alerts_count + responses_count + messages_count),
        "confidence_avg": round(float(weighted_avg), 3),
    }
