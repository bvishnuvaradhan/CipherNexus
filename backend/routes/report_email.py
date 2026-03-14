from datetime import datetime, timedelta
from uuid import uuid4
import os
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from database.repository import fetch_one, fetch_recent, insert_document, update_document

router = APIRouter()

DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


def _parse_time_of_day(value: str) -> tuple[int, int]:
    parts = (value or "").split(":")
    if len(parts) != 2:
        raise ValueError("time_of_day must be HH:MM")
    hour = int(parts[0])
    minute = int(parts[1])
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise ValueError("time_of_day must be HH:MM")
    return hour, minute


def _compute_initial_next_run(day_of_week: str, time_of_day: str, interval_minutes: int) -> str:
    now = datetime.utcnow()
    hour, minute = _parse_time_of_day(time_of_day)
    base = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

    if day_of_week in DAYS:
        target = DAYS.index(day_of_week)
        delta_days = (target - base.weekday()) % 7
        base = base + timedelta(days=delta_days)

    if base <= now:
        base = base + timedelta(minutes=max(5, interval_minutes))

    return base.isoformat()


class EmailReportScheduleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    day_of_week: str = Field(default="daily")
    time_of_day: str = Field(default="09:00")
    interval_minutes: int = Field(default=1440, ge=5, le=10080)
    lookback_hours: int = Field(default=24, ge=1, le=24 * 14)
    severity: str | None = None
    threat_types: list[str] = Field(default_factory=list)
    recipients: list[str] = Field(default_factory=list, min_length=1)

    @field_validator("day_of_week")
    @classmethod
    def validate_day(cls, value: str) -> str:
        day = (value or "daily").strip().lower()
        if day != "daily" and day not in DAYS:
            raise ValueError("day_of_week must be daily or monday..sunday")
        return day

    @field_validator("time_of_day")
    @classmethod
    def validate_time(cls, value: str) -> str:
        _parse_time_of_day(value)
        return value

    @field_validator("recipients")
    @classmethod
    def validate_recipients(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            address = (item or "").strip().lower()
            if not address:
                continue
            if "@" not in address or "." not in address:
                raise ValueError(f"Invalid email: {item}")
            cleaned.append(address)
        if not cleaned:
            raise ValueError("At least one valid recipient email is required")
        return sorted(set(cleaned))


@router.get("/contacts")
async def list_email_contacts():
    contacts = set()

    env_contacts = os.getenv("REPORT_EMAIL_CONTACTS", "")
    if env_contacts:
        for part in env_contacts.split(","):
            address = part.strip().lower()
            if address:
                contacts.add(address)

    schedules = await fetch_recent("email_report_schedules", limit=500, query={"deleted": {"$ne": True}})
    for schedule in schedules:
        for address in schedule.get("recipients", []) or []:
            if isinstance(address, str) and address.strip():
                contacts.add(address.strip().lower())

    return {"contacts": sorted(contacts)}


@router.get("/schedules")
async def list_email_report_schedules():
    schedules = await fetch_recent(
        "email_report_schedules",
        limit=200,
        query={"deleted": {"$ne": True}},
        sort_field="created_at",
    )
    return {"schedules": schedules, "total": len(schedules)}


@router.post("/schedules")
async def create_email_report_schedule(payload: EmailReportScheduleCreate):
    now = datetime.utcnow()
    schedule = {
        "id": str(uuid4()),
        "name": payload.name,
        "day_of_week": payload.day_of_week,
        "time_of_day": payload.time_of_day,
        "interval_minutes": payload.interval_minutes,
        "lookback_hours": payload.lookback_hours,
        "severity": payload.severity,
        "threat_types": sorted(set([item.strip() for item in payload.threat_types if item and item.strip()])),
        "recipients": payload.recipients,
        "enabled": True,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "last_run_at": None,
        "last_error": None,
        "next_run_at": _compute_initial_next_run(payload.day_of_week, payload.time_of_day, payload.interval_minutes),
    }
    await insert_document("email_report_schedules", schedule)
    return {"ok": True, "schedule": schedule}


@router.patch("/schedules/{schedule_id}")
async def toggle_email_schedule(schedule_id: str, enabled: bool = Query(...)):
    existing = await fetch_one("email_report_schedules", {"id": schedule_id, "deleted": {"$ne": True}})
    if not existing:
        raise HTTPException(status_code=404, detail="Email report schedule not found")

    patch = {"enabled": enabled, "updated_at": datetime.utcnow().isoformat()}
    if enabled:
        patch["next_run_at"] = _compute_initial_next_run(
            str(existing.get("day_of_week", "daily") or "daily"),
            str(existing.get("time_of_day", "09:00") or "09:00"),
            int(existing.get("interval_minutes", 1440) or 1440),
        )
    await update_document("email_report_schedules", {"id": schedule_id}, {"$set": patch})
    updated = await fetch_one("email_report_schedules", {"id": schedule_id})
    return {"ok": True, "schedule": updated}


@router.delete("/schedules/{schedule_id}")
async def delete_email_schedule(schedule_id: str):
    existing = await fetch_one("email_report_schedules", {"id": schedule_id, "deleted": {"$ne": True}})
    if not existing:
        raise HTTPException(status_code=404, detail="Email report schedule not found")
    await update_document(
        "email_report_schedules",
        {"id": schedule_id},
        {"$set": {"deleted": True, "enabled": False, "updated_at": datetime.utcnow().isoformat()}},
    )
    return {"ok": True}


@router.get("/runs")
async def list_email_report_runs(limit: int = Query(30, ge=1, le=200)):
    runs = await fetch_recent("email_report_runs", limit=limit, query={}, sort_field="sent_at")
    return {"runs": runs, "total": len(runs)}
