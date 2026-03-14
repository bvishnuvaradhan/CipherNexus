"""Forensics Agent — reconstructs incident timelines and investigation summaries."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from database.repository import save_agent_message, save_log
from models.schemas import LogEventType, SeverityLevel


class ForensicsAgent:
    NAME = "Forensics"
    ROLE = "Incident Investigation"
    RESPONSIBILITIES = [
        "Reconstruct attack timelines",
        "Collect and summarize incident evidence",
        "Generate post-incident investigation notes",
        "Support monitoring and future tuning",
    ]

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self.start_time = datetime.utcnow()
        self._message_bus = None

    def attach_bus(self, bus):
        self._message_bus = bus

    async def create_incident_report(
        self,
        alert: Dict[str, Any],
        response: Dict[str, Any],
        intel_result: Optional[Dict[str, Any]] = None,
        anomaly_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.status = "busy"
        target = response.get("target") or alert.get("source_ip") or "unknown"
        confidence = max(
            float(response.get("confidence", 0.0)),
            float((intel_result or {}).get("confidence", 0.0)),
            float((anomaly_result or {}).get("score", 0.0)),
        )
        timeline = [
            f"Alert detected: {alert.get('event', 'unknown')} from {target}",
            f"Response action: {response.get('action', 'observe')}",
        ]
        if intel_result and intel_result.get("matched"):
            timeline.append(f"Threat intel match: {intel_result.get('label')} ({intel_result.get('source')})")
        if anomaly_result:
            timeline.append(
                f"Anomaly score: {round(float(anomaly_result.get('score', 0.0)), 3)} => {anomaly_result.get('prediction', 'unknown')}"
            )

        summary = " | ".join(timeline)
        self._update_stats(f"Incident report for {target}", confidence)

        msg = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "from_agent": self.NAME,
            "to_agent": "Commander",
            "event": "incident_report_ready",
            "ip": target,
            "severity": alert.get("severity", "medium"),
            "payload": {
                "summary": summary,
                "timeline": timeline,
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
            "event_type": LogEventType.SYSTEM_EVENT.value,
            "agent": self.NAME,
            "severity": SeverityLevel.MEDIUM.value,
            "message": f"Forensics report created for {target}",
            "source_ip": target,
            "details": {"summary": summary},
        })
        self.status = "online"
        return {"summary": summary, "timeline": timeline}

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
        }
