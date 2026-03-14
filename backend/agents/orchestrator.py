"""
Agent Orchestrator
Bootstraps all agents, wires up the A2A message bus,
and runs the continuous monitoring / message-processing loops.
"""

from __future__ import annotations
import asyncio
import os
import random
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
        self.sentry.attach_bus(self._bus)
        self.detective.attach_bus(self._bus)
        self.commander.attach_bus(self._bus)
        self.response_automation.attach_bus(self._bus)
        self.forensics.attach_bus(self._bus)

        # Give Commander a direct handle to Detective and other agents for sync queries
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
        self._ws_manager = ws_manager
        self.commander.attach_ws_manager(ws_manager)
        self.sentry.attach_ws_manager(ws_manager)
        self.detective.attach_ws_manager(ws_manager)

    # ------------------------------------------------------------------
    # Main background loops
    # ------------------------------------------------------------------

    async def run_continuous_monitoring(self):
        self._running = True
        await asyncio.gather(
            # Disabled automatic threat generation - threats only come from Hacker Console
            # self.sentry.monitor_loop(interval=15.0),
            # self.detective.monitor_loop(interval=12.0),
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
        msg_type = msg.get("message_type", "alert")
        to_agent = msg.get("to_agent", "")
        event = msg.get("event", "")

        if self._ws_manager:
            await self._ws_manager.broadcast_agent_message(msg)

        if to_agent == "Commander" and msg_type == "alert":
<<<<<<< HEAD
            intel_result = self.threat_intelligence.assess_ip(msg.get("ip"))
            anomaly_result = await self._ml_score_live_alert(msg)
            payload = msg.get("payload", {}) or {}
            related_alert_id = payload.get("related_alert_id") or payload.get("alert_id") or msg.get("id")

            # Build a minimal alert dict for Commander
            alert = {
                "id": related_alert_id,
=======
            # Use alert_id from payload if provided, otherwise use message id
            payload = msg.get("payload", {})
            alert_id = payload.get("alert_id") or msg.get("id")
            alert = {
                "id": alert_id,
>>>>>>> origin/feature/enhanced-soc-platform
                "event": event,
                "threat_type": event,
                "severity": msg.get("severity", "medium"),
                "source_ip": msg.get("ip"),
                "confidence": payload.get("confidence", 0.70),
<<<<<<< HEAD
                "details": {
                    "threat_intelligence": intel_result,
                    "anomaly_detection": anomaly_result,
                },
=======
                "details": payload,  # Pass full payload as details for Commander
>>>>>>> origin/feature/enhanced-soc-platform
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
<<<<<<< HEAD
        """
        Periodically broadcast system status (threat level, agent status)
        to all connected WebSocket clients.
        """
        from database.repository import get_threat_level, get_agent_activity_metrics
=======
        from database.repository import get_threat_level
>>>>>>> origin/feature/enhanced-soc-platform

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
    # Public accessors
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

    async def trigger_simulation(
        self,
        attack_type: str,
        ip: str,
        intensity: str = "medium",
        target: str = "192.168.0.1",
        params: dict = None,
    ) -> dict:
        """
        Trigger a simulation from the Hacker Console.
        Routes to the appropriate agent based on attack type.
        """
        from models.schemas import AttackType, SeverityLevel

        params = params or {}
        intensity_map = {"low": 0.5, "medium": 0.75, "high": 0.95}

        # ── Brute Force ────────────────────────────────────────────────
        if attack_type == AttackType.BRUTE_FORCE.value:
            username = params.get("username", "root")
            count = params.get("attempt_count") or random.randint(6, 15)
            auth_protocol = params.get("auth_protocol", "ssh")
            password_list = params.get("password_list", "dictionary")
            alerts = []
            for _ in range(count):
                a = await self.detective.analyze_failed_login(ip, username, auth_protocol, password_list)
                if a:
                    alerts.append(a)
            if alerts:
<<<<<<< HEAD
                await self.detective.report_to_commander(
                    "brute_force_detected", ip, SeverityLevel.HIGH,
                    {
                        "failed_attempts": len(alerts),
                        "simulated": True,
                        "related_alert_id": alerts[-1].get("id"),
                    },
                )
            return {"triggered": "Detective", "alerts": len(alerts)}
=======
                last_alert = alerts[-1]
                # Call Commander directly (synchronous) instead of message bus
                commander_response = await self.commander.process_alert({
                    "id": last_alert.get("id"),
                    "event": "brute_force_detected",
                    "threat_type": "brute_force",
                    "severity": last_alert.get("severity", "high"),
                    "source_ip": ip,
                    "confidence": last_alert.get("confidence", 0.85),
                    "details": {"failed_attempts": len(alerts), "username": username},
                })
            return {"triggered": "Detective", "alert": alerts[-1] if alerts else None, "alerts_count": len(alerts), "username": username}
>>>>>>> origin/feature/enhanced-soc-platform

        # ── Port Scan ──────────────────────────────────────────────────
        elif attack_type == AttackType.PORT_SCAN.value:
            start = params.get("port_range_start", 1)
            end = params.get("port_range_end", 65535)
            scan_technique = params.get("scan_technique", "syn_stealth")
            scan_timing = params.get("scan_timing", "normal")
            count = random.randint(50, min(500, end - start + 1))
            ports = random.sample(range(start, end + 1), count)
            alert = await self.sentry.detect_port_scan(ip, ports, scan_technique, scan_timing)
            if alert:
<<<<<<< HEAD
                await self.sentry.report_to_commander(
                    "port_scan", ip, SeverityLevel(alert["severity"]),
                    {
                        "ports_count": len(ports),
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Sentry", "alert": alert}
=======
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "port_scan",
                    "threat_type": "port_scan",
                    "severity": alert.get("severity", "medium"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.75),
                    "details": {"ports_count": len(ports), "range": f"{start}-{end}"},
                })
            return {"triggered": "Sentry", "alert": alert, "ports_scanned": len(ports)}
>>>>>>> origin/feature/enhanced-soc-platform

        # ── Suspicious Login ───────────────────────────────────────────
        elif attack_type == AttackType.SUSPICIOUS_LOGIN.value:
            username = params.get("username", "admin")
            device_fingerprint = params.get("device_fingerprint", "unknown_device")
            location = random.choice(DetectiveAgent.SUSPICIOUS_LOCATIONS)
            alert = await self.detective.analyze_login_location(ip, username, location, device_fingerprint)
            if alert:
<<<<<<< HEAD
                await self.detective.report_to_commander(
                    "suspicious_login", ip, SeverityLevel(alert["severity"]),
                    {
                        "location": location,
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Detective", "alert": alert}
=======
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "suspicious_login",
                    "threat_type": "suspicious_login",
                    "severity": alert.get("severity", "medium"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.80),
                    "details": {"location": location, "username": username},
                })
            return {"triggered": "Detective", "alert": alert, "location": location}
>>>>>>> origin/feature/enhanced-soc-platform

        # ── Data Exfiltration ──────────────────────────────────────────
        elif attack_type == AttackType.DATA_EXFILTRATION.value:
            mb = params.get("payload_size_mb") or random.randint(80, 400)
            size = mb * 1024 * 1024
            exfil_protocol = params.get("exfil_protocol")
            destination_type = params.get("destination_type")
            exfil_encryption = params.get("exfil_encryption", "none")
            alert = await self.detective.analyze_data_exfiltration(ip, size, exfil_protocol, destination_type, exfil_encryption)
            if alert:
<<<<<<< HEAD
                await self.detective.report_to_commander(
                    "data_exfiltration", ip, SeverityLevel(alert["severity"]),
                    {
                        "megabytes": round(size / 1024 / 1024, 1),
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Detective", "alert": alert}
=======
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "data_exfiltration",
                    "threat_type": "data_exfiltration",
                    "severity": alert.get("severity", "critical"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.90),
                    "details": {"megabytes": mb, "protocol": exfil_protocol},
                })
            return {"triggered": "Detective", "alert": alert, "megabytes": mb}
>>>>>>> origin/feature/enhanced-soc-platform

        # ── Traffic Spike ──────────────────────────────────────────────
        elif attack_type == AttackType.TRAFFIC_SPIKE.value:
            rate = params.get("packet_rate") or random.randint(2000, 8000)
            spike_protocol = params.get("spike_protocol", "tcp")
            source_spoofing = params.get("source_spoofing", False)
            alert = await self.sentry.detect_traffic_spike(ip, rate, spike_protocol, source_spoofing)
            if alert:
<<<<<<< HEAD
                await self.sentry.report_to_commander(
                    "traffic_spike", ip, SeverityLevel(alert["severity"]),
                    {
                        "packet_rate": rate,
                        "simulated": True,
                        "related_alert_id": alert.get("id"),
                    },
                )
            return {"triggered": "Sentry", "alert": alert}
=======
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "traffic_spike",
                    "threat_type": "traffic_spike",
                    "severity": alert.get("severity", "high"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.85),
                    "details": {"packet_rate": rate},
                })
            return {"triggered": "Sentry", "alert": alert, "packet_rate": rate}

        # ── DDoS ──────────────────────────────────────────────────────
        elif attack_type == AttackType.DDOS.value:
            rate = params.get("packet_rate") or random.randint(8000, 25000)
            conns = random.randint(1000, 10000)
            flood_type = params.get("flood_type")
            botnet_size = params.get("botnet_size")
            alert = await self.sentry.detect_ddos(ip, rate, conns, flood_type, botnet_size)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "ddos",
                    "threat_type": "ddos",
                    "severity": alert.get("severity", "critical"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.95),
                    "details": {"packet_rate": rate, "concurrent_connections": conns},
                })
            return {"triggered": "Sentry", "alert": alert, "packet_rate": rate}

        # ── SQL Injection ──────────────────────────────────────────────
        elif attack_type == AttackType.SQL_INJECTION.value:
            injection_type = params.get("injection_type", "union")
            endpoint = params.get("target_endpoint") or f"/api/{random.choice(['login', 'users', 'search', 'products'])}"
            waf_evasion = params.get("waf_evasion", "none")
            database_type = params.get("database_type")
            alert = await self.detective.analyze_sql_injection(ip, endpoint, injection_type, waf_evasion, database_type)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "sql_injection",
                    "threat_type": "sql_injection",
                    "severity": alert.get("severity", "critical"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.90),
                    "details": {"injection_type": injection_type, "endpoint": endpoint},
                })
            return {"triggered": "Detective", "alert": alert, "injection_type": injection_type}

        # ── XSS ───────────────────────────────────────────────────────
        elif attack_type == AttackType.XSS.value:
            xss_type = params.get("xss_type", "reflected")
            endpoint = f"/{random.choice(['search', 'comment', 'profile', 'feedback'])}"
            payload_encoding = params.get("payload_encoding", "none")
            alert = await self.detective.analyze_xss_attack(ip, xss_type, endpoint, payload_encoding)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "xss_attack",
                    "threat_type": "xss",
                    "severity": alert.get("severity", "high"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.85),
                    "details": {"xss_type": xss_type, "endpoint": endpoint},
                })
            return {"triggered": "Detective", "alert": alert, "xss_type": xss_type}

        # ── Ransomware ─────────────────────────────────────────────────
        elif attack_type == AttackType.RANSOMWARE.value:
            spread_rate = params.get("spread_rate", "medium")
            encryption_algo = params.get("encryption_algo")
            ransom_family = params.get("ransom_family")
            alert = await self.detective.analyze_ransomware(ip, spread_rate, encryption_algo, ransom_family)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "ransomware",
                    "threat_type": "ransomware",
                    "severity": alert.get("severity", "critical"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.95),
                    "details": {"spread_rate": spread_rate, "family": ransom_family},
                })
            return {"triggered": "Detective", "alert": alert, "spread_rate": spread_rate}

        # ── MITM ──────────────────────────────────────────────────────
        elif attack_type == AttackType.MITM.value:
            protocol = params.get("target_protocol", "http")
            mitm_technique = params.get("mitm_technique", "arp_poison")
            capture_type = params.get("capture_type", "credentials")
            alert = await self.sentry.detect_mitm(ip, protocol, mitm_technique, capture_type)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "mitm",
                    "threat_type": "mitm",
                    "severity": alert.get("severity", "critical"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.90),
                    "details": {"target_protocol": protocol, "technique": mitm_technique},
                })
            return {"triggered": "Sentry", "alert": alert, "protocol": protocol}

        # ── DNS Spoofing ───────────────────────────────────────────────
        elif attack_type == AttackType.DNS_SPOOFING.value:
            domain = params.get("target_domain", "internal.corp")
            redirect_target = params.get("redirect_target")
            record_type = params.get("record_type", "A")
            alert = await self.sentry.detect_dns_spoofing(ip, domain, redirect_target, record_type)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "dns_spoofing",
                    "threat_type": "dns_spoofing",
                    "severity": alert.get("severity", "high"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.85),
                    "details": {"target_domain": domain},
                })
            return {"triggered": "Sentry", "alert": alert, "domain": domain}

        # ── C2 Beacon ─────────────────────────────────────────────────
        elif attack_type == AttackType.COMMAND_CONTROL.value:
            interval = params.get("beacon_interval", 60)
            c2_protocol = params.get("c2_protocol")
            persistence_method = params.get("persistence_method")
            jitter_percent = params.get("jitter_percent", 0)
            alert = await self.sentry.detect_c2_beacon(ip, interval, c2_protocol, persistence_method, jitter_percent)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "command_control",
                    "threat_type": "command_control",
                    "severity": alert.get("severity", "critical"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.90),
                    "details": {"beacon_interval": interval, "protocol": c2_protocol},
                })
            return {"triggered": "Sentry", "alert": alert, "beacon_interval": interval}
>>>>>>> origin/feature/enhanced-soc-platform

        return {"triggered": "none", "reason": "unknown attack type"}
