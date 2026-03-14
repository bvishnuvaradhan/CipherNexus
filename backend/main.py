"""
AI Multi-Agent Cybersecurity Defense System
FastAPI Backend - Main Application Entry Point
"""

import asyncio
import os
import uvicorn
from dotenv import load_dotenv

# Load environment variables from backend/.env when present
load_dotenv()
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from database.connection import connect_to_mongo, close_mongo_connection
from routes.alerts import router as alerts_router
from routes.logs import router as logs_router
from routes.agents import router as agents_router
from routes.responses import router as responses_router
from routes.simulator import router as simulator_router
from routes.data import router as data_router
from routes.ml import router as ml_router
from routes.auth import router as auth_router
from routes.labs import router as labs_router
from routes.report_email import router as report_email_router
from websocket.manager import websocket_router, manager as ws_manager
from agents.orchestrator import AgentOrchestrator
from services.report_scheduler import ReportScheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    # Startup
    await connect_to_mongo()
    orchestrator = AgentOrchestrator()
    orchestrator.attach_ws_manager(ws_manager)
    app.state.orchestrator = orchestrator
    await orchestrator.initialize()
    asyncio.create_task(orchestrator.run_core_services())
    report_scheduler = ReportScheduler()
    await report_scheduler.start()
    app.state.report_scheduler = report_scheduler
    auto_monitoring = os.getenv("AUTO_MONITORING", "false").lower() == "true"
    if auto_monitoring:
        asyncio.create_task(orchestrator.run_continuous_monitoring())
        print("[OK] Auto monitoring enabled")
    else:
        print("[OK] Auto monitoring disabled (no continuous data generation)")
    print("[OK] AI Cyber Defense System initialized - all agents online")
    yield
    # Shutdown
    await app.state.report_scheduler.stop()
    await close_mongo_connection()
    print("[OK] System shutdown - agents offline")


app = FastAPI(
    title="AI Multi-Agent Cybersecurity Defense System",
    description="Real-time SOC platform powered by multi-agent AI architecture",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
app.include_router(logs_router, prefix="/logs", tags=["Logs"])
app.include_router(agents_router, prefix="/agents", tags=["Agents"])
app.include_router(responses_router, prefix="/responses", tags=["Responses"])
app.include_router(simulator_router, prefix="/simulate-attack", tags=["Simulator"])
app.include_router(data_router, prefix="/data", tags=["Data"])
app.include_router(ml_router, prefix="/ml", tags=["ML"])
app.include_router(labs_router, prefix="/labs", tags=["Labs"])
app.include_router(report_email_router, prefix="/email-reports", tags=["Email Reports"])
app.include_router(websocket_router, tags=["WebSocket"])


@app.get("/", tags=["Health"])
async def root():
    return {
        "system": "AI Multi-Agent Cybersecurity Defense System",
        "status": "operational",
        "version": "2.0.0",
        "agents": ["Sentry", "Detective", "Commander"],
    }


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "agents_online": 3}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
