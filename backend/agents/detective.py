"""
Detective Agent — Log Intelligence
Responsibilities: analyze login attempts, detect brute force attacks,
detect abnormal login locations, analyze system logs.
"""

from __future__ import annotations
import asyncio
import random
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from models.schemas import (
    AgentName, SeverityLevel, AttackType, AlertStatus, LogEventType,
)
from database.repository import save_alert, save_log, save_agent_message


class DetectiveAgent:
    """
    Detective analyzes authentication logs and system events to spot
    brute force attacks, credential stuffing, and abnormal activity.
    """

    NAME = AgentName.DETECTIVE
    ROLE = "Log Intelligence"
    RESPONSIBILITIES = [
        "Analyze login attempts",
        "Detect brute force attacks",
        "Flag abnormal login locations",
        "Analyze system logs",
    ]

    BRUTE_FORCE_THRESHOLD = 5  # failed logins in window
    BRUTE_FORCE_WINDOW = 300   # seconds

    # Simulated "normal" locations
    NORMAL_LOCATIONS = ["New York", "London", "San Francisco", "Chicago", "Seattle"]
    SUSPICIOUS_LOCATIONS = ["Unknown", "TOR Exit Node", "Moscow", "Beijing", "Pyongyang"]

    USERNAMES = ["root", "admin", "administrator", "ubuntu", "deploy", "git", "user1"]

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self._message_bus = None
        self._failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.start_time = datetime.utcnow()

    def attach_bus(self, bus):
        self._message_bus = bus

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    async def analyze_failed_login(self, ip: str, username: str) -> Optional[Dict]:
        """Track failed logins and raise alert on brute force threshold."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.BRUTE_FORCE_WINDOW)

        # Prune old attempts
        self._failed_attempts[ip] = [
            t for t in self._failed_attempts[ip] if t > window_start
        ]
        self._failed_attempts[ip].append(now)

        await self._log_event(
            LogEventType.LOGIN_FAILED,
            f"Failed login attempt for '{username}' from {ip}",
            ip=ip,
            severity=SeverityLevel.LOW,
            user=username,
        )

        attempt_count = len(self._failed_attempts[ip])
        if attempt_count >= self.BRUTE_FORCE_THRESHOLD:
            confidence = min(0.99, 0.70 + (attempt_count * 0.02))
            severity = SeverityLevel.CRITICAL if attempt_count > 20 else SeverityLevel.HIGH

            alert = {
                "id": str(uuid.uuid4()),
                "timestamp": now.isoformat(),
                "agent": self.NAME.value,
                "event": "Brute Force Attack Detected",
                "threat_type": AttackType.BRUTE_FORCE.value,
                "severity": severity.value,
                "source_ip": ip,
                "target": username,
                "status": AlertStatus.ACTIVE.value,
                "confidence": round(confidence, 3),
                "details": {
                    "failed_attempts": attempt_count,
                    "username": username,
                    "window_seconds": self.BRUTE_FORCE_WINDOW,
                },
            }
            await save_alert(alert)
            self._update_stats("Brute force detected", confidence)
            return alert
        return None

    async def analyze_login_location(self, ip: str, username: str, location: str) -> Optional[Dict]:
        """Flag logins from suspicious or unusual geographic locations."""
        is_suspicious = location in self.SUSPICIOUS_LOCATIONS
        if not is_suspicious:
            await self._log_event(
                LogEventType.LOGIN_SUCCESS,
                f"Login from '{username}' at {location} — normal",
                ip=ip, severity=SeverityLevel.LOW, user=username,
            )
            return None

        confidence = random.uniform(0.70, 0.90)
        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "Suspicious Login Location",
            "threat_type": AttackType.SUSPICIOUS_LOGIN.value,
            "severity": SeverityLevel.MEDIUM.value,
            "source_ip": ip,
            "target": username,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {"location": location, "username": username},
        }
        await save_alert(alert)
        await self._log_event(
            LogEventType.LOGIN_FAILED,
            f"Suspicious login location for '{username}': {location}",
            ip=ip, severity=SeverityLevel.MEDIUM, user=username,
        )
        self._update_stats("Suspicious location detected", confidence)
        return alert

    async def analyze_data_exfiltration(self, ip: str, bytes_transferred: int) -> Optional[Dict]:
        """Detect unusually large outbound data transfers."""
        threshold = 50 * 1024 * 1024  # 50 MB
        if bytes_transferred < threshold:
            return None

        confidence = min(0.99, 0.65 + (bytes_transferred / (500 * 1024 * 1024)))
        severity = SeverityLevel.CRITICAL if bytes_transferred > 200 * 1024 * 1024 else SeverityLevel.HIGH

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "Data Exfiltration Suspected",
            "threat_type": AttackType.DATA_EXFILTRATION.value,
            "severity": severity.value,
            "source_ip": ip,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {
                "bytes_transferred": bytes_transferred,
                "threshold_bytes": threshold,
                "megabytes": round(bytes_transferred / (1024 * 1024), 2),
            },
        }
        await save_alert(alert)
        await self._log_event(
            LogEventType.DATA_TRANSFER,
            f"Large data transfer from {ip}: {round(bytes_transferred / 1024 / 1024, 1)} MB",
            ip=ip, severity=severity,
        )
        self._update_stats("Data exfiltration detected", confidence)
        return alert

    # ------------------------------------------------------------------
    # Verification query handler (called by Commander)
    # ------------------------------------------------------------------

    async def verify_ip(self, ip: str) -> Dict:
        """Return login history and threat assessment for a given IP."""
        failed = len(self._failed_attempts.get(ip, []))
        threat_level = "clean"
        confidence = 0.1

        if failed >= self.BRUTE_FORCE_THRESHOLD:
            threat_level = "brute_force"
            confidence = min(0.99, 0.70 + failed * 0.02)
        elif failed > 0:
            threat_level = "suspicious"
            confidence = 0.4 + failed * 0.05

        result = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME.value,
            "to_agent": AgentName.COMMANDER.value,
            "event": "ip_verification_result",
            "ip": ip,
            "payload": {
                "failed_logins": failed,
                "threat_level": threat_level,
                "confidence": round(confidence, 3),
            },
            "message_type": "response",
        }
        await save_agent_message(result)
        if self._message_bus:
            await self._message_bus.put(result)
        return result

    # ------------------------------------------------------------------
    # A2A communication
    # ------------------------------------------------------------------

    async def report_to_commander(self, event: str, ip: str, severity: SeverityLevel, payload: Dict = None) -> Dict:
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

    # ------------------------------------------------------------------
    # Continuous monitoring loop
    # ------------------------------------------------------------------

    async def monitor_loop(self, interval: float = 12.0):
        while True:
            await asyncio.sleep(interval)
            await self._run_log_analysis_cycle()

    async def _run_log_analysis_cycle(self):
        self.status = "busy"
        ip = self._random_ip()
        username = random.choice(self.USERNAMES)

        roll = random.random()
        if roll < 0.20:
            # Simulate multiple failed logins → brute force
            alert = None
            for _ in range(random.randint(5, 12)):
                alert = await self.analyze_failed_login(ip, username)
            if alert:
                await self.report_to_commander(
                    "brute_force_detected", ip, SeverityLevel(alert["severity"]),
                    {
                        "failed_attempts": alert["details"]["failed_attempts"],
                        "related_alert_id": alert.get("id"),
                    },
                )
        elif roll < 0.30:
            location = random.choice(self.SUSPICIOUS_LOCATIONS)
            alert = await self.analyze_login_location(ip, username, location)
            if alert:
                await self.report_to_commander(
                    "suspicious_login", ip, SeverityLevel(alert["severity"]),
                    {
                        "location": location,
                        "related_alert_id": alert.get("id"),
                    },
                )
        elif roll < 0.35:
            size = random.randint(60 * 1024 * 1024, 300 * 1024 * 1024)
            alert = await self.analyze_data_exfiltration(ip, size)
            if alert:
                await self.report_to_commander(
                    "data_exfiltration", ip, SeverityLevel(alert["severity"]),
                    {
                        "megabytes": round(size / 1024 / 1024, 1),
                        "related_alert_id": alert.get("id"),
                    },
                )
        else:
            # Normal login — just log it
            location = random.choice(self.NORMAL_LOCATIONS)
            await self.analyze_login_location(ip, username, location)

        self.status = "online"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _log_event(
        self, event_type: LogEventType, message: str,
        ip: Optional[str] = None, severity: SeverityLevel = SeverityLevel.LOW,
        user: Optional[str] = None,
    ):
        log = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "agent": self.NAME.value,
            "severity": severity.value,
            "message": message,
            "source_ip": ip,
            "user": user,
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
