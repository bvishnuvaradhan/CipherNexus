"""Data management endpoints for loading realistic sample records."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from database.seed_data import seed_real_data

router = APIRouter()


class SeedDataRequest(BaseModel):
    alerts: int = Field(default=30, ge=1, le=2000)
    logs: int = Field(default=80, ge=1, le=5000)
    responses: int = Field(default=20, ge=1, le=2000)
    agent_messages: int = Field(default=40, ge=1, le=3000)
    attacks: int = Field(default=15, ge=1, le=1000)
    seed: int = Field(default=20260314)


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
