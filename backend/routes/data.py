"""Data management endpoints — seed data removed, all data is live-generated."""

from fastapi import APIRouter
from database.connection import get_db
from database.mock_store import get_mock_collection

router = APIRouter()


@router.delete("/clear")
async def clear_all_data():
    """Clear all alerts, responses, and logs from the database."""
    db = get_db()
    cleared = []

    if db is not None:
        # Clear MongoDB
        await db.alerts.delete_many({})
        await db.responses.delete_many({})
        await db.logs.delete_many({})
        await db.agent_messages.delete_many({})
        await db.attacks.delete_many({})
        cleared.append("mongodb")

    # Also clear mock store
    for col in ["alerts", "responses", "logs", "agent_messages", "attacks"]:
        mock = get_mock_collection(col)
        await mock.delete_many({})
    cleared.append("mock_store")

    return {"status": "cleared", "stores": cleared}
