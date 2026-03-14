"""Authentication route — simple JWT-style token for demo purposes."""

from fastapi import APIRouter, HTTPException
from models.schemas import LoginRequest, LoginResponse
import secrets

router = APIRouter()

# Demo credentials (in production, use a proper user store + bcrypt)
DEMO_USERS = {
    "admin": "cyber2026",
    "analyst": "soc2026",
    "demo": "demo",
}


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    stored = DEMO_USERS.get(credentials.username)
    if not stored or stored != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(32)
    return LoginResponse(access_token=token, username=credentials.username)


@router.post("/logout")
async def logout():
    return {"message": "Logged out successfully"}
