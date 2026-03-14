"""
Pydantic Models — domain entities for the AI Cyber Defense System.
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field
import uuid


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentName(str, Enum):
    SENTRY = "Sentry"
    DETECTIVE = "Detective"
    COMMANDER = "Commander"
    THREAT_INTELLIGENCE = "Threat Intelligence"
    ANOMALY_DETECTION = "Anomaly Detection"
    RESPONSE_AUTOMATION = "Response Automation"
    FORENSICS = "Forensics"
    SYSTEM = "System"


class AlertStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    BLOCKED = "blocked"


class ResponseStatus(str, Enum):
    BLOCKED = "blocked"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    PENDING = "pending"


class AttackType(str, Enum):
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_LOGIN = "suspicious_login"
    DATA_EXFILTRATION = "data_exfiltration"
    TRAFFIC_SPIKE = "traffic_spike"
    MALWARE = "malware"


class LogEventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    PORT_SCAN = "port_scan"
    TRAFFIC_SPIKE = "traffic_spike"
    DATA_TRANSFER = "data_transfer"
    FIREWALL_BLOCK = "firewall_block"
    SYSTEM_EVENT = "system_event"
    AGENT_ACTION = "agent_action"


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: AgentName
    event: str
    threat_type: AttackType
    severity: SeverityLevel
    source_ip: Optional[str] = None
    target: Optional[str] = None
    status: AlertStatus = AlertStatus.ACTIVE
    details: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class LogEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: LogEventType
    agent: AgentName
    severity: SeverityLevel
    message: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class AgentMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    from_agent: AgentName
    to_agent: AgentName
    event: str
    ip: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    message_type: str = "alert"  # alert | query | response | action


class AutoResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str
    target: str
    agent: AgentName = AgentName.COMMANDER
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    status: ResponseStatus = ResponseStatus.PENDING
    related_alert_id: Optional[str] = None
    signals: List[str] = Field(default_factory=list)


class AttackSimulation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    attack_type: AttackType
    source_ip: str
    target: str = "192.168.0.1"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    detected: bool = False
    mitigated: bool = False


class AgentStatus(BaseModel):
    name: AgentName
    status: str = "online"  # online | offline | busy | alert
    role: str
    responsibilities: List[str]
    last_action: Optional[str] = None
    last_action_time: Optional[datetime] = None
    threat_count: int = 0
    confidence_avg: float = 0.0
    uptime_seconds: int = 0


# ---------------------------------------------------------------------------
# API Request / Response schemas
# ---------------------------------------------------------------------------

class SimulateAttackRequest(BaseModel):
    attack_type: AttackType
    source_ip: Optional[str] = None
    intensity: Optional[str] = "medium"  # low | medium | high


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class ThreatLevelResponse(BaseModel):
    level: str  # LOW | MEDIUM | HIGH | CRITICAL
    score: int  # 0–100
    active_alerts: int
    top_threat: Optional[str] = None


class WSMessage(BaseModel):
    type: str  # alert | agent_message | response | threat_level | log | status
    data: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
