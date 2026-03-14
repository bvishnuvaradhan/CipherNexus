"""
MongoDB Connection Manager
Handles database connection lifecycle and provides collection accessors.
"""

import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ServerSelectionTimeoutError
from typing import Optional

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_client: Optional[AsyncIOMotorClient] = None
_db = None

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "cyber_defense")


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------

async def connect_to_mongo():
    global _client, _db
    try:
        _client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5000)
        _db = _client[DB_NAME]
        # Verify connection
        await _client.admin.command("ping")
        print(f"[OK] MongoDB connected: {MONGO_URL}/{DB_NAME}")
        await _ensure_indexes()
    except ServerSelectionTimeoutError:
        print("[WARN] MongoDB unavailable - running in in-memory mock mode")
        _client = None
        _db = None


async def close_mongo_connection():
    global _client
    if _client:
        _client.close()
        print("[OK] MongoDB connection closed")


async def _ensure_indexes():
    """Create indexes for performance."""
    if _db is None:
        return
    await _db.alerts.create_index([("timestamp", -1)])
    await _db.logs.create_index([("timestamp", -1)])
    await _db.responses.create_index([("timestamp", -1)])
    await _db.agent_messages.create_index([("timestamp", -1)])
    await _db.attacks.create_index([("timestamp", -1)])


# ---------------------------------------------------------------------------
# Collection accessors
# ---------------------------------------------------------------------------

def get_db():
    return _db


def get_collection(name: str):
    if _db is None:
        raise RuntimeError("Database not connected")
    return _db[name]
