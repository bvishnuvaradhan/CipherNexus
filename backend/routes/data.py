"""Data management endpoints — seed data removed, all data is live-generated."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from database.seed_data import seed_real_data
from database.repository import clear_collections
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

    # Also clear mock store if available
    try:
        for col in ["alerts", "responses", "logs", "agent_messages", "attacks"]:
            mock = get_mock_collection(col)
            if mock:
                await mock.delete_many({})
        cleared.append("mock_store")
    except Exception:
        pass

    return {"status": "cleared", "stores": cleared}


class SeedDataRequest(BaseModel):
    alerts: int = Field(default=20, ge=1, le=1000)
    logs: int = Field(default=100, ge=1, le=5000)
    responses: int = Field(default=10, ge=0, le=500)
    agent_messages: int = Field(default=40, ge=1, le=3000)
    attacks: int = Field(default=5, ge=1, le=100)
    seed: int = Field(default=42)


@router.post("/seed-real")
async def seed_real(payload: SeedDataRequest):
    inserted = await seed_real_data(
        alerts=payload.alerts,
        logs=payload.logs,
        responses=payload.responses,
        agent_messages=payload.agent_messages,
        attacks=payload.attacks,
        seed=payload.seed,
    )
    return {
        "message": "Realistic SOC data inserted",
        "inserted": inserted,
        "seed": payload.seed,
    }


class ClearDataRequest(BaseModel):
    confirm: bool = Field(default=False)
    collections: list[str] = Field(
        default_factory=lambda: ["alerts", "logs", "agent_messages", "responses", "attacks"]
    )


@router.post("/clear")
async def clear_data(payload: ClearDataRequest):
    if not payload.confirm:
        return {
            "message": "No data deleted. Set confirm=true to clear collections.",
            "deleted": {},
        }

    deleted = await clear_collections(payload.collections)
    return {
        "message": "Collections cleared",
        "deleted": deleted,
    }
