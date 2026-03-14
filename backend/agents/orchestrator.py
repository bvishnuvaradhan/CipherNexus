"""
Agent Orchestrator
Bootstraps all agents, wires up the A2A message bus,
and runs the continuous monitoring / message-processing loops.
"""

from __future__ import annotations
import asyncio
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from agents.sentry import SentryAgent
from agents.detective import DetectiveAgent
from agents.commander import CommanderAgent
from agents.threat_intelligence import ThreatIntelligenceAgent
from agents.anomaly_detection import AnomalyDetectionAgent
from agents.response_automation import ResponseAutomationAgent
from agents.forensics import ForensicsAgent
from database.repository import save_alert


class AgentOrchestrator:
    """
    Central wiring class:
    - Instantiates Sentry, Detective, Commander
    - Creates the shared asyncio Queue (A2A message bus)
    - Injects dependencies between agents
    - Starts all background monitoring loops
    """

    def __init__(self):
        self.sentry = SentryAgent()
        self.detective = DetectiveAgent()
        self.commander = CommanderAgent()
        self.threat_intelligence = ThreatIntelligenceAgent()
        self.anomaly_detection = AnomalyDetectionAgent()
        self.response_automation = ResponseAutomationAgent()
        self.forensics = ForensicsAgent()
        self._bus: asyncio.Queue = asyncio.Queue()
        self._ws_manager: Optional[object] = None
        self._running = False
        self._minimum_resolution_seconds = 30

    async def initialize(self):
        """Wire up agents and inject shared dependencies."""
        # Attach the A2A message bus
        self.sentry.attach_bus(self._bus)
        self.detective.attach_bus(self._bus)
        self.commander.attach_bus(self._bus)
        self.response_automation.attach_bus(self._bus)
        self.forensics.attach_bus(self._bus)

        # Give Commander a direct handle to Detective for sync queries
        self.commander.attach_detective(self.detective)
        self.commander.attach_threat_intelligence(self.threat_intelligence)
        self.commander.attach_anomaly_detection(self.anomaly_detection)
        self.commander.attach_response_automation(self.response_automation)
        self.commander.attach_forensics(self.forensics)

        print("[ONLINE] Sentry Agent")
        print("[ONLINE] Detective Agent")
        print("[ONLINE] Commander Agent")
        print("[ONLINE] Threat Intelligence Agent")
        print("[ONLINE] Anomaly Detection Agent")
        print("[ONLINE] Response Automation Agent")
        print("[ONLINE] Forensics Agent")

    def attach_ws_manager(self, ws_manager):
        """Inject the WebSocket manager for live broadcasts."""
        self._ws_manager = ws_manager
        self.commander.attach_ws_manager(ws_manager)

    # ------------------------------------------------------------------
    # Main background loops
    # ------------------------------------------------------------------

    async def run_continuous_monitoring(self):
        """
        Starts all agent loops concurrently:
        - Sentry network monitoring
        - Detective log analysis
        - A2A message bus processing
        """
        self._running = True
        await asyncio.gather(
            self.sentry.monitor_loop(interval=15.0),
            self.detective.monitor_loop(interval=12.0),
        )

    async def run_core_services(self):
        """Run core non-synthetic background services required for app behavior."""
        await asyncio.gather(
            self._process_message_bus(),
            self._push_live_events(),
            self._resolve_monitoring_by_time(),
            self._unblock_blocked_by_time(),
        )

    async def _unblock_blocked_by_time(self):
        """Auto-unblock blocked incidents after TTL and mark them resolved."""
        from database.repository import (
            count_documents,
            get_due_blocked_responses,
            resolve_blocked_responses_for_alert,
            save_response,
            update_incident_alerts_status,
            fetch_one,
            has_recent_incident_activity,
        )

        while True:
            await asyncio.sleep(5)
            try:
                timeout_seconds = max(int(os.getenv("BLOCK_AUTO_UNBLOCK_SECONDS", "60")), self._minimum_resolution_seconds)
            except Exception:
                timeout_seconds = 60

            if timeout_seconds <= 0:
                continue

            cutoff_iso = (datetime.utcnow() - timedelta(seconds=timeout_seconds)).isoformat()

            try:
                due = await get_due_blocked_responses(cutoff_iso=cutoff_iso, limit=100)
                processed_alerts: set[str] = set()
                for row in due:
                    alert_id = row.get("related_alert_id")
                    target = row.get("target", "unknown")

                    if not alert_id or alert_id in processed_alerts:
                        continue
                    processed_alerts.add(alert_id)

                    already_resolved = await count_documents(
                        "responses",
                        {"related_alert_id": alert_id, "status": "resolved"},
                    )
                    if already_resolved > 0:
                        await resolve_blocked_responses_for_alert(
                            alert_id,
                            {
                                "updated_by": "SystemUnblockResolver",
                                "reason": "Resolved response already exists for alert",
                            },
                        )
                        continue

                    if await has_recent_incident_activity(alert_id, cutoff_iso):
                        continue

                    converted = await resolve_blocked_responses_for_alert(
                        alert_id,
                        {
                            "updated_by": "SystemUnblockResolver",
                            "reason": f"Block TTL reached ({timeout_seconds}s)",
                        },
                    )

                    release_result = await self.response_automation.release_target(
                        target,
                        reason=f"block_ttl_elapsed_{timeout_seconds}s",
                    )

                    resolution_response = {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.utcnow().isoformat(),
                        "action": f"Auto-unblock IP {target}",
                        "target": target,
                        "agent": "Commander",
                        "confidence": 0.7,
                        "reasoning": f"Block duration reached {timeout_seconds}s TTL. Target unblocked and incident resolved.",
                        "status": "resolved",
                        "related_alert_id": alert_id,
                        "signals": [
                            f"[SystemUnblockResolver] Block TTL elapsed ({timeout_seconds}s)",
                            f"[SystemUnblockResolver] Converted blocked responses: {converted}",
                            f"[Response Automation] released={release_result.get('released', False)}",
                            "[SystemUnblockResolver] Incident auto-resolved after unblock",
                        ],
                    }
                    await save_response(resolution_response)

                    updated_result = await update_incident_alerts_status(
                        alert_id,
                        "resolved",
                        {
                            "phase": "resolved",
                            "updated_by": "SystemUnblockResolver",
                            "resolved_at": datetime.utcnow().isoformat(),
                            "resolution": "Block TTL elapsed; target auto-unblocked",
                            "target": target,
                        },
                    )
                    updated_alert = updated_result.get("alert")

                    if self._ws_manager:
                        await self._ws_manager.broadcast_response(resolution_response)
                        if updated_alert:
                            await self._ws_manager.broadcast_alert(updated_alert)
                        else:
                            fallback_alert = await fetch_one("alerts", {"id": alert_id})
                            if fallback_alert:
                                await self._ws_manager.broadcast_alert(fallback_alert)
            except Exception as e:
                print(f"[WARN] Block TTL resolver error: {e}")

    async def _resolve_monitoring_by_time(self):
        """Resolve monitoring incidents when their timeout window elapses."""
        from database.repository import (
            count_documents,
            get_due_monitoring_responses,
            resolve_monitoring_responses_for_alert,
            save_response,
            update_incident_alerts_status,
            fetch_one,
            has_recent_incident_activity,
        )

        while True:
            await asyncio.sleep(5)
            try:
                timeout_seconds = max(int(os.getenv("MONITORING_AUTO_RESOLVE_SECONDS", "30")), self._minimum_resolution_seconds)
            except Exception:
                timeout_seconds = 30

            if timeout_seconds <= 0:
                continue

            cutoff_iso = (datetime.utcnow() - timedelta(seconds=timeout_seconds)).isoformat()

            try:
                due = await get_due_monitoring_responses(cutoff_iso=cutoff_iso, limit=100)
                for row in due:
                    alert_id = row.get("related_alert_id")
                    target = row.get("target", "unknown")

                    if not alert_id:
                        continue

                    already_resolved = await count_documents(
                        "responses",
                        {"related_alert_id": alert_id, "status": "resolved"},
                    )
                    if already_resolved > 0:
                        await resolve_monitoring_responses_for_alert(
                            alert_id,
                            {
                                "updated_by": "SystemTimeoutResolver",
                                "reason": "Resolved response already exists for alert",
                            },
                        )
                        continue

                    if await has_recent_incident_activity(alert_id, cutoff_iso):
                        continue

                    converted = await resolve_monitoring_responses_for_alert(
                        alert_id,
                        {
                            "updated_by": "SystemTimeoutResolver",
                            "reason": f"Monitoring timeout reached ({timeout_seconds}s)",
                        },
                    )

                    resolution_response = {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.utcnow().isoformat(),
                        "action": f"Auto-resolve monitored incident for IP {target}",
                        "target": target,
                        "agent": "Commander",
                        "confidence": 0.6,
                        "reasoning": f"No escalation during {timeout_seconds}s monitoring window. Incident auto-resolved.",
                        "status": "resolved",
                        "related_alert_id": alert_id,
                        "signals": [
                            f"[SystemTimeoutResolver] Monitoring timer elapsed ({timeout_seconds}s)",
                            f"[SystemTimeoutResolver] Converted monitoring responses: {converted}",
                            "[SystemTimeoutResolver] Incident auto-resolved",
                        ],
                    }
                    await save_response(resolution_response)

                    updated_result = await update_incident_alerts_status(
                        alert_id,
                        "resolved",
                        {
                            "phase": "resolved",
                            "updated_by": "SystemTimeoutResolver",
                            "resolved_at": datetime.utcnow().isoformat(),
                            "resolution": "Monitoring window elapsed without escalation",
                            "target": target,
                        },
                    )
                    updated_alert = updated_result.get("alert")

                    if self._ws_manager:
                        await self._ws_manager.broadcast_response(resolution_response)
                        if updated_alert:
                            await self._ws_manager.broadcast_alert(updated_alert)
                        elif alert_id:
                            fallback_alert = await fetch_one("alerts", {"id": alert_id})
                            if fallback_alert:
                                await self._ws_manager.broadcast_alert(fallback_alert)
            except Exception as e:
                print(f"[WARN] Monitoring timeout resolver error: {e}")

    async def _process_message_bus(self):
        """
        Consumes messages from the A2A bus.
        Routes them to Commander for decision-making and WS broadcast.
        """
        while True:
            try:
                msg = await asyncio.wait_for(self._bus.get(), timeout=5.0)
                await self._handle_message(msg)
                self._bus.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"[WARN] Bus error: {e}")

    async def _handle_message(self, msg: dict):
        """Route an A2A message to the appropriate handler."""
        msg_type = msg.get("message_type", "alert")
        from_agent = msg.get("from_agent", "")
        to_agent = msg.get("to_agent", "")
        event = msg.get("event", "")

        # Broadcast every message to WebSocket clients
        if self._ws_manager:
            await self._ws_manager.broadcast_agent_message(msg)

        # Commander processes alerts from field agents
        if to_agent == "Commander" and msg_type == "alert":
            intel_result = self.threat_intelligence.assess_ip(msg.get("ip"))
            anomaly_result = await self._ml_score_live_alert(msg)
            payload = msg.get("payload", {}) or {}
            related_alert_id = payload.get("related_alert_id") or payload.get("alert_id") or msg.get("id")

            # Build a minimal alert dict for Commander
            alert = {
                "id": related_alert_id,
                "event": event,
                "threat_type": event,
                "severity": msg.get("severity", "medium"),
                "source_ip": msg.get("ip"),
                "confidence": payload.get("confidence", 0.70),
                "details": {
                    "threat_intelligence": intel_result,
                    "anomaly_detection": anomaly_result,
                },
            }
            await self.commander.process_alert(alert)

    async def _ml_score_live_alert(self, msg: dict):
        """Run ML scoring on live A2A alert messages and push correlated alerts."""
        try:
            flow_features = self._build_flow_features_from_msg(msg)
            ml_result = self.anomaly_detection.analyze_flow(flow_features, msg.get("event", "live_alert"))

            if self._ws_manager:
                await self._ws_manager.broadcast({
                    "type": "ml_prediction",
                    "data": {
                        "source_message_id": msg.get("id"),
                        "source_agent": msg.get("from_agent"),
                        "event": msg.get("event"),
                        "source_ip": msg.get("ip"),
                        "result": ml_result,
                    },
                })

            if ml_result.get("anomaly"):
                score = float(ml_result.get("score", 0.0))
                correlated_alert = {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat(),
                    "agent": "System",
                    "event": "ML Correlated Alert",
                    "threat_type": msg.get("event", "unknown"),
                    "severity": self._severity_from_score(score),
                    "source_ip": msg.get("ip"),
                    "status": "active",
                    "confidence": round(score, 3),
                    "details": {
                        "origin": "orchestrator_message_bus",
                        "source_agent": msg.get("from_agent"),
                        "source_message_id": msg.get("id"),
                        "ml_prediction": ml_result,
                    },
                }
                await save_alert(correlated_alert)
                if self._ws_manager:
                    await self._ws_manager.broadcast_alert(correlated_alert)
            return ml_result
        except FileNotFoundError:
            # Allow platform to run without trained artifacts.
            return {"prediction": "unavailable", "reason": "model_not_trained"}
        except Exception as e:
            print(f"[WARN] ML live-scoring failed: {e}")
            return {"prediction": "error", "reason": str(e)}

    def _severity_from_score(self, score: float) -> str:
        if score >= 0.9:
            return "critical"
        if score >= 0.75:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    def _build_flow_features_from_msg(self, msg: dict) -> dict:
        payload = msg.get("payload", {}) or {}
        event = str(msg.get("event", "")).lower()

        port = 80
        if "port_scan" in event:
            port = 22
        elif "brute_force" in event:
            port = 22
        elif "data_exfiltration" in event:
            port = 443
        elif "suspicious_login" in event:
            port = 3389

        packet_rate = float(payload.get("packet_rate", 1200))
        ports_count = float(payload.get("ports_count", 20))
        failed_attempts = float(payload.get("failed_attempts", 5))
        megabytes = float(payload.get("megabytes", 30))

        return {
            "Destination Port": port,
            "Flow Duration": max(300, int(1000 + failed_attempts * 100)),
            "Total Fwd Packets": max(5, int(ports_count / 2)),
            "Total Backward Packets": max(3, int(failed_attempts + 3)),
            "Flow Bytes/s": max(1000, int(megabytes * 1024)),
            "Flow Packets/s": max(1.0, round(packet_rate / 100.0, 2)),
        }

    async def _push_live_events(self):
        """
        Periodically broadcast system status (threat level, agent status)
        to all connected WebSocket clients.
        """
        from database.repository import get_threat_level, get_agent_activity_metrics

        while True:
            await asyncio.sleep(10)
            if self._ws_manager:
                try:
                    threat = await get_threat_level()
                    await self._ws_manager.broadcast_threat_level(threat)
                    statuses = [
                        self.sentry.get_status(),
                        self.detective.get_status(),
                        self.commander.get_status(),
                        self.threat_intelligence.get_status(),
                        self.anomaly_detection.get_status(),
                        self.response_automation.get_status(),
                        self.forensics.get_status(),
                    ]
                    persisted = await asyncio.gather(*[
                        get_agent_activity_metrics(agent.get("name", ""))
                        for agent in statuses
                    ])
                    merged = []
                    for status, metric in zip(statuses, persisted):
                        item = dict(status)
                        item["threat_count"] = max(int(item.get("threat_count", 0) or 0), int(metric.get("threat_count", 0) or 0))
                        item["confidence_avg"] = max(float(item.get("confidence_avg", 0.0) or 0.0), float(metric.get("confidence_avg", 0.0) or 0.0))
                        merged.append(item)
                    status = {"agents": merged}
                    await self._ws_manager.broadcast_status(status)
                except Exception as e:
                    print(f"[WARN] Status push error: {e}")

    # ------------------------------------------------------------------
    # Public accessors (used by routes)
    # ------------------------------------------------------------------

    def get_all_agent_statuses(self):
        return [
            self.sentry.get_status(),
            self.detective.get_status(),
            self.commander.get_status(),
            self.threat_intelligence.get_status(),
            self.anomaly_detection.get_status(),
            self.response_automation.get_status(),
            self.forensics.get_status(),
        ]

    async def trigger_simulation(self, attack_type: str, ip: str, intensity: str = "medium") -> dict:
        """
        Manually trigger a simulation from the Attack Simulator page.
        Routes to the appropriate agent based on attack type.
        """
        from models.schemas import AttackType, SeverityLevel
        import random

        intensity_map = {"low": 0.5, "medium": 0.75, "high": 0.95}
        intensity_confidence = intensity_map.get(intensity, 0.75)

        if attack_type == AttackType.BRUTE_FORCE.value:
            alerts = []
            for _ in range(random.randint(6, 15)):
                a = await self.detective.analyze_failed_login(ip, "root")
                if a:
                    alerts.append(a)
            if alerts:
                await self.detective.report_to_commander(
                    "brute_force_detected", ip, SeverityLevel.HIGH,
                    {
                        "failed_attempts": len(alerts),
                        "simulated": True,
                        "related_alert_id": alerts[-1].get("id"),
                    },
                )
            return {"triggered": "Detective", "alerts": len(alerts)}

        elif attack_type == AttackType.PORT_SCAN.value:
            ports = random.sample(range(1, 65535), random.randint(50, 500))
            alert = await self.sentry.detect_port_scan(ip, ports)
            if alert:
                await self.sentry.report_to_commander(
                    "port_scan", ip, SeverityLevel(alert["severity"]),
                    {
                        "ports_count": len(ports),
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Sentry", "alert": alert}

        elif attack_type == AttackType.SUSPICIOUS_LOGIN.value:
            from agents.detective import DetectiveAgent
            location = random.choice(DetectiveAgent.SUSPICIOUS_LOCATIONS)
            alert = await self.detective.analyze_login_location(ip, "admin", location)
            if alert:
                await self.detective.report_to_commander(
                    "suspicious_login", ip, SeverityLevel(alert["severity"]),
                    {
                        "location": location,
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Detective", "alert": alert}

        elif attack_type == AttackType.DATA_EXFILTRATION.value:
            size = random.randint(80 * 1024 * 1024, 400 * 1024 * 1024)
            alert = await self.detective.analyze_data_exfiltration(ip, size)
            if alert:
                await self.detective.report_to_commander(
                    "data_exfiltration", ip, SeverityLevel(alert["severity"]),
                    {
                        "megabytes": round(size / 1024 / 1024, 1),
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Detective", "alert": alert}

        elif attack_type == AttackType.TRAFFIC_SPIKE.value:
            rate = random.randint(2000, 8000)
            alert = await self.sentry.detect_traffic_spike(ip, rate)
            if alert:
                await self.sentry.report_to_commander(
                    "traffic_spike", ip, SeverityLevel(alert["severity"]),
                    {
                        "packet_rate": rate,
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Sentry", "alert": alert}

        return {"triggered": "none", "reason": "unknown attack type"}
