"""Authentication routes — SOC analyst and hacker console access."""

from fastapi import APIRouter, HTTPException
from models.schemas import LoginRequest, LoginResponse
import secrets

router = APIRouter()

# SOC analyst credentials
SOC_USERS = {
    "admin": "cyber2026",
    "analyst": "soc2026",
}

# Hacker console credentials (separate access portal)
HACKER_USERS = {
    "phantom": "h4ck3r2026",
    "shadow": "darkweb99",
    "ghost": "r00t4cc3ss",
    "zero": "zd4y_2026",
}


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    stored = SOC_USERS.get(credentials.username)
    if not stored or stored != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(32)
    return LoginResponse(access_token=token, username=credentials.username)


@router.post("/hacker-login", response_model=LoginResponse)
async def hacker_login(credentials: LoginRequest):
    stored = HACKER_USERS.get(credentials.username)
    if not stored or stored != credentials.password:
        raise HTTPException(status_code=401, detail="Access denied — invalid operator credentials")
    token = secrets.token_hex(32)
    return LoginResponse(access_token=token, username=credentials.username)


@router.post("/logout")
async def logout():
    return {"message": "Logged out successfully"}
