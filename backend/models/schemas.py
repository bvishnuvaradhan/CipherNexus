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
    DDOS = "ddos"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RANSOMWARE = "ransomware"
    MITM = "mitm"
    DNS_SPOOFING = "dns_spoofing"
    COMMAND_CONTROL = "command_control"


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
    target_ip: Optional[str] = "192.168.0.1"
    intensity: Optional[str] = "medium"  # low | medium | high
    # Login / brute-force parameters
    username: Optional[str] = None
    attempt_count: Optional[int] = None
    auth_protocol: Optional[str] = None       # ssh | rdp | http_basic | ldap
    password_list: Optional[str] = None       # rockyou | dictionary | custom
    # Port scan parameters
    port_range_start: Optional[int] = None
    port_range_end: Optional[int] = None
    scan_technique: Optional[str] = None      # syn_stealth | tcp_connect | udp | xmas | null_scan
    scan_timing: Optional[str] = None         # paranoid | sneaky | normal | aggressive
    # Suspicious login parameters
    device_fingerprint: Optional[str] = None  # unknown_device | mobile_emulator | headless_browser
    # Data exfiltration parameters
    payload_size_mb: Optional[int] = None
    exfil_protocol: Optional[str] = None      # https | dns_tunnel | ftp | sftp | icmp
    destination_type: Optional[str] = None    # external_cloud | tor_exit | foreign_asn
    exfil_encryption: Optional[str] = None    # none | aes256 | custom
    # Traffic / DDoS parameters
    packet_rate: Optional[int] = None
    flood_type: Optional[str] = None          # udp | tcp_syn | http | slowloris | amplification
    botnet_size: Optional[int] = None
    spike_protocol: Optional[str] = None      # udp | tcp | icmp | http
    source_spoofing: Optional[bool] = None
    # SQL injection parameters
    injection_type: Optional[str] = None      # sql: union | blind | time_based
    target_endpoint: Optional[str] = None
    waf_evasion: Optional[str] = None         # none | encoding | case_switch | comment_injection
    database_type: Optional[str] = None       # mysql | postgresql | mssql | oracle
    # XSS parameters
    xss_type: Optional[str] = None            # xss: reflected | stored | dom
    payload_encoding: Optional[str] = None    # none | base64 | url_encode | html_entities
    # Ransomware parameters
    spread_rate: Optional[str] = None         # ransomware: slow | medium | fast
    encryption_algo: Optional[str] = None     # aes256 | rsa2048 | chacha20
    ransom_family: Optional[str] = None       # lockbit | blackcat | cl0p | revil
    # MITM parameters
    target_protocol: Optional[str] = None     # mitm: http | https | ftp
    mitm_technique: Optional[str] = None      # arp_poison | ssl_strip | dns_hijack
    capture_type: Optional[str] = None        # credentials | full_traffic | selective
    # DNS spoofing parameters
    target_domain: Optional[str] = None       # dns_spoofing: domain to hijack
    redirect_target: Optional[str] = None     # IP to redirect to
    record_type: Optional[str] = None         # A | AAAA | CNAME | MX
    # C2 beacon parameters
    beacon_interval: Optional[int] = None     # c2: seconds between beacons
    c2_protocol: Optional[str] = None         # https | dns_tunnel | irc | custom
    persistence_method: Optional[str] = None  # registry | scheduled_task | wmi | service
    jitter_percent: Optional[int] = None      # 0-50, randomness in beacon timing
    # General
    duration_seconds: Optional[int] = 30


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
