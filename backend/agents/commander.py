"""
Commander Agent — Decision Engine
Responsibilities: gather signals from Sentry and Detective,
determine threat severity, initiate mitigation actions.
Implements Explainable AI (XAI) reasoning paths.
"""

from __future__ import annotations
import asyncio
import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from models.schemas import (
    AgentName, SeverityLevel, AttackType, ResponseStatus, LogEventType,
)
from database.repository import save_response, save_log, save_agent_message


class CommanderAgent:
    """
    Commander is the central decision-maker.  It receives signals from
    Sentry and Detective, requests cross-verification, then executes
    automated responses with explainable reasoning (XAI).
    """

    NAME = AgentName.COMMANDER
    ROLE = "Decision Engine"
    RESPONSIBILITIES = [
        "Correlate signals from Sentry & Detective",
        "Determine threat severity",
        "Initiate mitigation actions",
        "Generate XAI reasoning paths",
    ]

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self._message_bus = None
        self._detective: Any = None   # injected
        self.start_time = datetime.utcnow()
        self._blocked_ips: set = set()
        self._ws_manager: Any = None  # injected for live push

    def attach_bus(self, bus):
        self._message_bus = bus

    def attach_detective(self, detective):
        self._detective = detective

    def attach_ws_manager(self, ws_manager):
        self._ws_manager = ws_manager

    # ------------------------------------------------------------------
    # Core decision pipeline
    # ------------------------------------------------------------------

    async def process_alert(self, alert: Dict) -> Optional[Dict]:
        """
        Main entry-point: receives an alert, runs cross-agent verification,
        then decides on a response.
        """
        self.status = "busy"
        ip = alert.get("source_ip") or alert.get("ip", "unknown")
        severity = SeverityLevel(alert.get("severity", "medium"))
        threat_type = alert.get("threat_type", alert.get("event", "unknown"))

        # Step 1 — request Detective verification
        verification = await self._request_detective_verification(ip)
        detective_confirms = False
        detective_detail = ""

        if verification:
            payload = verification.get("payload", {})
            detective_confirms = payload.get("threat_level") in ("brute_force", "suspicious")
            failed = payload.get("failed_logins", 0)
            detective_detail = f"{failed} failed login attempts confirmed by Detective" if detective_confirms else "No suspicious login activity found"

        # Step 2 — build XAI reasoning
        reasoning, confidence = self._build_reasoning(
            alert, verification, detective_confirms
        )

        # Step 3 — decide action
        action, response_status = self._decide_action(severity, confidence, ip, threat_type)

        # Step 4 — persist response with XAI
        response = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "target": ip,
            "agent": self.NAME.value,
            "confidence": round(confidence, 3),
            "reasoning": reasoning,
            "status": response_status.value,
            "related_alert_id": alert.get("id"),
            "signals": self._build_signals(alert, detective_confirms, detective_detail),
        }
        await save_response(response)
        await self._log_action(action, ip, confidence)
        self._update_stats(action, confidence)

        # Step 5 — broadcast via WebSocket
        if self._ws_manager:
            await self._ws_manager.broadcast_response(response)

        self.status = "online"
        return response

    # ------------------------------------------------------------------
    # Explainable AI
    # ------------------------------------------------------------------

    def _build_reasoning(
        self, alert: Dict, verification: Optional[Dict], detective_confirms: bool
    ) -> tuple[str, float]:
        """
        Construct a human-readable reasoning chain and confidence score.
        This is the XAI component.
        """
        parts: List[str] = []
        confidence = alert.get("confidence", 0.5)

        # Sentry signal
        sentry_event = alert.get("event", "Unknown event")
        parts.append(f"{sentry_event} detected by Sentry Agent from IP {alert.get('source_ip', 'unknown')}")

        # Cross-agent correlation
        if detective_confirms:
            payload = (verification or {}).get("payload", {})
            failed = payload.get("failed_logins", 0)
            parts.append(f"Cross-correlated with {failed} failed login attempts confirmed by Detective Agent")
            confidence = min(0.99, confidence + 0.15)
        else:
            parts.append("Detective Agent found no corroborating login anomalies")
            confidence = max(0.30, confidence - 0.10)

        # Severity uplift
        sev = alert.get("severity", "medium")
        if sev in ("high", "critical"):
            parts.append(f"Severity classified as {sev.upper()} — immediate response warranted")
            confidence = min(0.99, confidence + 0.05)

        return " → ".join(parts) + ".", round(confidence, 3)

    def _build_signals(self, alert: Dict, detective_confirms: bool, detective_detail: str) -> List[str]:
        signals = [f"[Sentry] {alert.get('event', 'Anomaly detected')} from {alert.get('source_ip', 'unknown')}"]
        if detective_confirms:
            signals.append(f"[Detective] {detective_detail}")
        signals.append(f"[Commander] Threat severity: {alert.get('severity', 'unknown').upper()}")
        return signals

    def _decide_action(
        self, severity: SeverityLevel, confidence: float, ip: str, threat_type: str
    ) -> tuple[str, ResponseStatus]:
        """Map severity + confidence onto a concrete response action."""
        if confidence >= 0.85 and severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            self._blocked_ips.add(ip)
            return f"Block IP {ip}", ResponseStatus.BLOCKED
        elif confidence >= 0.65 or severity == SeverityLevel.MEDIUM:
            return f"Monitor IP {ip} — elevated watch", ResponseStatus.MONITORING
        else:
            return f"Log and observe IP {ip}", ResponseStatus.MONITORING

    # ------------------------------------------------------------------
    # A2A coordination
    # ------------------------------------------------------------------

    async def _request_detective_verification(self, ip: str) -> Optional[Dict]:
        """Ask Detective to cross-check an IP."""
        if not self._detective:
            return None

        # Send A2A query message
        query = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME.value,
            "to_agent": AgentName.DETECTIVE.value,
            "event": "verify_ip",
            "ip": ip,
            "payload": {},
            "message_type": "query",
        }
        await save_agent_message(query)
        if self._message_bus:
            await self._message_bus.put(query)

        # Get Detective's response directly
        return await self._detective.verify_ip(ip)

    async def coordinate_response(self, sentry_alert: Dict, detective_alert: Dict) -> Dict:
        """
        Full collaborative workflow:
        Sentry reports → Commander queries Detective → combined response.
        """
        combined_confidence = (
            sentry_alert.get("confidence", 0.5) + detective_alert.get("confidence", 0.5)
        ) / 2 * 1.1  # boost for corroboration

        ip = sentry_alert.get("source_ip", detective_alert.get("source_ip", "unknown"))
        reasoning = (
            f"{sentry_alert.get('event')} reported by Sentry. "
            f"Corroborated by Detective: {detective_alert.get('event')}. "
            f"Combined confidence score: {round(combined_confidence, 2)}."
        )

        response = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "action": f"Block IP {ip}",
            "target": ip,
            "agent": self.NAME.value,
            "confidence": round(min(0.99, combined_confidence), 3),
            "reasoning": reasoning,
            "status": ResponseStatus.BLOCKED.value,
            "signals": [
                f"[Sentry] {sentry_alert.get('event')}",
                f"[Detective] {detective_alert.get('event')}",
                "[Commander] Dual-agent corroboration → block executed",
            ],
        }
        await save_response(response)
        if self._ws_manager:
            await self._ws_manager.broadcast_response(response)
        return response

    async def broadcast_command(self, target_agent: AgentName, command: str, payload: Dict = None) -> Dict:
        msg = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME.value,
            "to_agent": target_agent.value,
            "event": command,
            "payload": payload or {},
            "message_type": "action",
        }
        await save_agent_message(msg)
        if self._message_bus:
            await self._message_bus.put(msg)
        return msg

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _log_action(self, action: str, ip: str, confidence: float):
        log = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": LogEventType.AGENT_ACTION.value,
            "agent": self.NAME.value,
            "severity": SeverityLevel.HIGH.value,
            "message": f"Commander executed: {action} (confidence: {confidence:.2f})",
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
            "blocked_ips_count": len(self._blocked_ips),
        }
