"""Response Automation Agent — executes containment actions after confirmation."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from database.repository import save_log, save_agent_message
from models.schemas import LogEventType, SeverityLevel


class ResponseAutomationAgent:
    NAME = "Response Automation"
    ROLE = "Defensive Execution"
    RESPONSIBILITIES = [
        "Execute containment actions after threat confirmation",
        "Block malicious IPs and isolate targets",
        "Trigger administrator notifications",
        "Track execution outcomes for automated response",
    ]

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self.start_time = datetime.utcnow()
        self._executed_targets: set[str] = set()
        self._message_bus = None

    def attach_bus(self, bus):
        self._message_bus = bus

    async def execute_action(self, response: Dict[str, Any]) -> Dict[str, Any]:
        self.status = "busy"
        target = response.get("target", "unknown")
        action = response.get("action", "observe")
        confidence = float(response.get("confidence", 0.0))
        normalized_status = str(response.get("status", "pending")).lower()
        execution_status = "executed"

        if target in self._executed_targets and normalized_status == "blocked":
            execution_status = "already_enforced"
        elif normalized_status == "blocked":
            self._executed_targets.add(target)

        self._update_stats(f"{action} [{execution_status}]", confidence)

        msg = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME,
            "to_agent": "Commander",
            "event": "response_executed",
            "ip": target,
            "severity": response.get("status", "monitoring"),
            "payload": {
                "action": action,
                "execution_status": execution_status,
                "confidence": confidence,
            },
            "message_type": "response",
        }
        await save_agent_message(msg)
        if self._message_bus:
            await self._message_bus.put(msg)

        await save_log({
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": LogEventType.AGENT_ACTION.value,
            "agent": self.NAME,
            "severity": SeverityLevel.HIGH.value if normalized_status == "blocked" else SeverityLevel.MEDIUM.value,
            "message": f"Response Automation executed '{action}' for {target} ({execution_status})",
            "source_ip": target,
            "details": {"execution_status": execution_status},
        })
        self.status = "online"
        return {"execution_status": execution_status, "target": target, "action": action}

    async def release_target(self, target: str, reason: str = "ttl_expired") -> Dict[str, Any]:
        """Release a previously blocked target (auto-unblock/manual-unblock)."""
        self.status = "busy"
        was_blocked = target in self._executed_targets
        if was_blocked:
            self._executed_targets.discard(target)

        self._update_stats(f"Release target {target} [{reason}]", 0.7 if was_blocked else 0.5)

        msg = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME,
            "to_agent": "Commander",
            "event": "target_released",
            "ip": target,
            "severity": "resolved",
            "payload": {
                "reason": reason,
                "released": was_blocked,
            },
            "message_type": "response",
        }
        await save_agent_message(msg)
        if self._message_bus:
            await self._message_bus.put(msg)

        await save_log({
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": LogEventType.AGENT_ACTION.value,
            "agent": self.NAME,
            "severity": SeverityLevel.MEDIUM.value,
            "message": f"Response Automation released target {target} ({reason})",
            "source_ip": target,
            "details": {"reason": reason, "released": was_blocked},
        })

        self.status = "online"
        return {"released": was_blocked, "target": target, "reason": reason}

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
            "name": self.NAME,
            "status": self.status,
            "role": self.ROLE,
            "responsibilities": self.RESPONSIBILITIES,
            "last_action": self.last_action,
            "last_action_time": self.last_action_time.isoformat() if self.last_action_time else None,
            "threat_count": self.threat_count,
            "confidence_avg": self._avg_confidence(),
            "uptime_seconds": uptime,
            "executed_targets": len(self._executed_targets),
        }
