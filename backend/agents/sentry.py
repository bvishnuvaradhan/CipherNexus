"""
Sentry Agent — Network Defense
Responsibilities: monitor network traffic, detect traffic spikes,
port scans, and suspicious IPs.
"""

from __future__ import annotations
import asyncio
import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from models.schemas import (
    AgentName, SeverityLevel, AttackType, AlertStatus,
    LogEventType, AgentMessage,
)
from database.repository import save_alert, save_log, save_agent_message


class SentryAgent:
    """
    Sentry monitors inbound/outbound network traffic and flags anomalies.
    It communicates findings to Commander via the A2A protocol.
    """

    NAME = AgentName.SENTRY
    ROLE = "Network Defense"
    RESPONSIBILITIES = [
        "Monitor network traffic",
        "Detect traffic spikes",
        "Identify port scans",
        "Flag suspicious IPs",
    ]

    # Known suspicious IP ranges (simulated)
    SUSPICIOUS_IP_RANGES = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113."]

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self._message_bus = None  # Injected by orchestrator
        self.start_time = datetime.utcnow()

    def attach_bus(self, bus):
        """Attach the shared A2A message bus."""
        self._message_bus = bus

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    async def detect_traffic_spike(self, ip: str, packet_rate: int) -> Optional[Dict]:
        """Detect abnormal traffic volume from a single source."""
        threshold = 1000  # packets/sec
        if packet_rate < threshold:
            return None

        severity = SeverityLevel.HIGH if packet_rate > 3000 else SeverityLevel.MEDIUM
        confidence = min(0.99, 0.6 + (packet_rate / 10000))

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "Traffic Spike Detected",
            "threat_type": AttackType.TRAFFIC_SPIKE.value,
            "severity": severity.value,
            "source_ip": ip,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {"packet_rate": packet_rate, "threshold": threshold},
        }
        await save_alert(alert)
        await self._log_event(
            LogEventType.TRAFFIC_SPIKE,
            f"Traffic spike detected from {ip}: {packet_rate} pkt/s",
            ip=ip,
            severity=severity,
        )
        self._update_stats("Traffic spike detected", confidence)
        return alert

    async def detect_port_scan(self, ip: str, ports_scanned: List[int]) -> Optional[Dict]:
        """Identify sequential or broad port scanning patterns."""
        if len(ports_scanned) < 10:
            return None

        confidence = min(0.99, 0.55 + (len(ports_scanned) / 200))
        severity = SeverityLevel.HIGH if len(ports_scanned) > 100 else SeverityLevel.MEDIUM

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "Port Scan Detected",
            "threat_type": AttackType.PORT_SCAN.value,
            "severity": severity.value,
            "source_ip": ip,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {
                "ports_scanned": len(ports_scanned),
                "sample_ports": ports_scanned[:10],
            },
        }
        await save_alert(alert)
        await self._log_event(
            LogEventType.PORT_SCAN,
            f"Port scan detected from {ip}: {len(ports_scanned)} ports probed",
            ip=ip,
            severity=severity,
        )
        self._update_stats("Port scan detected", confidence)
        return alert

    async def detect_suspicious_ip(self, ip: str, reason: str) -> Optional[Dict]:
        """Flag an IP that matches known threat indicators."""
        confidence = random.uniform(0.65, 0.90)
        severity = SeverityLevel.MEDIUM

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "Suspicious IP Flagged",
            "threat_type": AttackType.TRAFFIC_SPIKE.value,
            "severity": severity.value,
            "source_ip": ip,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {"reason": reason},
        }
        await save_alert(alert)
        await self._log_event(
            LogEventType.FIREWALL_BLOCK,
            f"Suspicious IP flagged: {ip} — {reason}",
            ip=ip,
            severity=severity,
        )
        self._update_stats("Suspicious IP flagged", confidence)
        return alert

    # ------------------------------------------------------------------
    # A2A communication
    # ------------------------------------------------------------------

    async def report_to_commander(self, event: str, ip: str, severity: SeverityLevel, payload: Dict = None) -> Dict:
        """Send an A2A message to Commander."""
        msg = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME.value,
            "to_agent": AgentName.COMMANDER.value,
            "event": event,
            "ip": ip,
            "severity": severity.value,
            "payload": payload or {},
            "message_type": "alert",
        }
        await save_agent_message(msg)
        if self._message_bus:
            await self._message_bus.put(msg)
        return msg

    async def respond_to_query(self, query: Dict) -> Dict:
        """Respond to status/verification queries from Commander."""
        response = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME.value,
            "to_agent": query.get("from_agent", AgentName.COMMANDER.value),
            "event": "status_report",
            "payload": {
                "status": self.status,
                "threat_count": self.threat_count,
                "last_action": self.last_action,
                "confidence_avg": self._avg_confidence(),
            },
            "message_type": "response",
        }
        await save_agent_message(response)
        if self._message_bus:
            await self._message_bus.put(response)
        return response

    # ------------------------------------------------------------------
    # Continuous monitoring loop
    # ------------------------------------------------------------------

    async def monitor_loop(self, interval: float = 15.0):
        """Periodically simulate network monitoring (background task)."""
        while True:
            await asyncio.sleep(interval)
            await self._run_monitoring_cycle()

    async def _run_monitoring_cycle(self):
        """Simulate a single round of network analysis."""
        self.status = "busy"
        ip = self._random_ip()

        roll = random.random()
        if roll < 0.15:
            ports = random.sample(range(1, 65535), random.randint(15, 200))
            alert = await self.detect_port_scan(ip, ports)
            if alert:
                await self.report_to_commander(
                    "port_scan", ip, SeverityLevel(alert["severity"]),
                    {
                        "ports_count": len(ports),
                        "related_alert_id": alert.get("id"),
                    },
                )
        elif roll < 0.25:
            rate = random.randint(1100, 8000)
            alert = await self.detect_traffic_spike(ip, rate)
            if alert:
                await self.report_to_commander(
                    "traffic_spike", ip, SeverityLevel(alert["severity"]),
                    {
                        "packet_rate": rate,
                        "related_alert_id": alert.get("id"),
                    },
                )
        elif roll < 0.30:
            alert = await self.detect_suspicious_ip(ip, "Threat intelligence match")
            if alert:
                await self.report_to_commander(
                    "suspicious_ip", ip, SeverityLevel(alert["severity"]), {"related_alert_id": alert.get("id")}
                )

        self.status = "online"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _log_event(
        self, event_type: LogEventType, message: str,
        ip: Optional[str] = None, severity: SeverityLevel = SeverityLevel.MEDIUM,
    ):
        log = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "agent": self.NAME.value,
            "severity": severity.value,
            "message": message,
            "source_ip": ip,
        }
        await save_log(log)

    def _update_stats(self, action: str, confidence: float):
        self.threat_count += 1
        self.last_action = action
        self.last_action_time = datetime.utcnow()
        self.confidence_scores.append(confidence)
        if len(self.confidence_scores) > 100:
            self.confidence_scores.pop(0)

    def _avg_confidence(self) -> float:
        if not self.confidence_scores:
            return 0.0
        return round(sum(self.confidence_scores) / len(self.confidence_scores), 3)

    @staticmethod
    def _random_ip() -> str:
        prefixes = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113.", "198.51.100."]
        return random.choice(prefixes) + str(random.randint(1, 254))

    def get_status(self) -> Dict[str, Any]:
        uptime = int((datetime.utcnow() - self.start_time).total_seconds())
        return {
            "name": self.NAME.value,
            "status": self.status,
            "role": self.ROLE,
            "responsibilities": self.RESPONSIBILITIES,
            "last_action": self.last_action,
            "last_action_time": self.last_action_time.isoformat() if self.last_action_time else None,
            "threat_count": self.threat_count,
            "confidence_avg": self._avg_confidence(),
            "uptime_seconds": uptime,
        }
