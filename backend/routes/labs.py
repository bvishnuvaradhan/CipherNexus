"""Labs — manage isolated attack simulation lab instances."""

import secrets
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

# In-memory lab instance store (one active lab at a time per deployment)
_labs: dict = {}


class CreateLabRequest(BaseModel):
    name: str
    description: Optional[str] = None


@router.get("")
async def list_labs():
    return {"labs": list(_labs.values())}


@router.get("/active")
async def get_active_lab():
    """Return the currently running lab instance, or None."""
    for lab in _labs.values():
        if lab["status"] == "running":
            return {"lab": lab}
    return {"lab": None}


@router.post("")
async def create_lab(data: CreateLabRequest):
    """Create a new lab instance. Only one running lab allowed at a time."""
    for lab in _labs.values():
        if lab["status"] == "running":
            raise HTTPException(
                status_code=409,
                detail="A lab instance is already running. Destroy it before creating a new one.",
            )

    lab_id = str(uuid.uuid4())
    lab = {
        "id": lab_id,
        "name": data.name,
        "description": data.description or "Attack simulation lab environment",
        "status": "running",
        "created_at": datetime.utcnow().isoformat(),
        "token": secrets.token_hex(16),
        "attack_count": 0,
    }
    _labs[lab_id] = lab
    return {"lab": lab}


@router.patch("/{lab_id}/increment")
async def increment_attack_count(lab_id: str):
    """Increment the attack counter for a lab (called after each attack)."""
    lab = _labs.get(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab instance not found")
    lab["attack_count"] = lab.get("attack_count", 0) + 1
    return {"lab": lab}


@router.delete("/{lab_id}")
async def destroy_lab(lab_id: str):
    """Terminate and destroy a lab instance."""
    lab = _labs.pop(lab_id, None)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab instance not found")
    lab["status"] = "destroyed"
    lab["destroyed_at"] = datetime.utcnow().isoformat()
    return {"message": "Lab instance destroyed", "lab": lab}
