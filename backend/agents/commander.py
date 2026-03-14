"""
Commander Agent — Decision Engine
Responsibilities: gather signals from Sentry and Detective,
determine threat severity, initiate mitigation actions.
Implements Explainable AI (XAI) reasoning paths.
"""

from __future__ import annotations
import asyncio
import os
import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from models.schemas import (
    AgentName, SeverityLevel, AttackType, ResponseStatus, LogEventType,
)
from database.repository import (
    save_response,
    save_log,
    save_agent_message,
    update_incident_alerts_status,
    mark_attacks_mitigated,
    fetch_one,
    fetch_recent,
    resolve_monitoring_responses_for_alert,
    resolve_blocked_responses_for_alert,
)


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
    MIN_RESOLUTION_SECONDS = 30
    MONITORING_AUTO_RESOLVE_SECONDS = max(
        int(os.getenv("MONITORING_AUTO_RESOLVE_SECONDS", "30")),
        MIN_RESOLUTION_SECONDS,
    )
    CONFIDENCE_BASELINE = float(os.getenv("COMMANDER_CONFIDENCE_BASELINE", "0.65"))
    CONFIDENCE_BONUS_DETECTIVE = float(os.getenv("COMMANDER_CONFIDENCE_BONUS_DETECTIVE", "0.18"))
    CONFIDENCE_BONUS_INTEL_FACTOR = float(os.getenv("COMMANDER_CONFIDENCE_BONUS_INTEL_FACTOR", "0.14"))
    CONFIDENCE_BONUS_ANOMALY = float(os.getenv("COMMANDER_CONFIDENCE_BONUS_ANOMALY", "0.10"))
    CONFIDENCE_BONUS_SEVERITY = float(os.getenv("COMMANDER_CONFIDENCE_BONUS_SEVERITY", "0.08"))
    CONFIDENCE_PENALTY_NO_CORROBORATION = float(os.getenv("COMMANDER_CONFIDENCE_PENALTY_NO_CORROBORATION", "0.04"))
    BRUTE_FORCE_BLOCK_CONFIDENCE = float(os.getenv("COMMANDER_BRUTE_FORCE_BLOCK_CONFIDENCE", "0.90"))
    BRUTE_FORCE_MONITOR_BLOCK_SECONDS = max(5, int(os.getenv("COMMANDER_BRUTE_FORCE_MONITOR_BLOCK_SECONDS", "20")))

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self._message_bus = None
        self._detective: Any = None   # injected
        self._threat_intelligence: Any = None
        self._anomaly_detection: Any = None
        self._response_automation: Any = None
        self._forensics: Any = None
        self.start_time = datetime.utcnow()
        self._blocked_ips: set = set()
        self._lifecycle_reconcile_inflight: set[str] = set()
        self._ws_manager: Any = None  # injected for live push

    def attach_bus(self, bus):
        self._message_bus = bus

    def attach_detective(self, detective):
        self._detective = detective

    def attach_threat_intelligence(self, threat_intelligence):
        self._threat_intelligence = threat_intelligence

    def attach_anomaly_detection(self, anomaly_detection):
        self._anomaly_detection = anomaly_detection

    def attach_response_automation(self, response_automation):
        self._response_automation = response_automation

    def attach_forensics(self, forensics):
        self._forensics = forensics

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
        related_alert_id = alert.get("id")

        if related_alert_id:
            await self._set_alert_lifecycle(
                related_alert_id,
                "investigating",
                {"phase": "analysis", "updated_by": self.NAME.value, "target": ip},
            )

        # Step 1 — request Detective verification
        verification = await self._request_detective_verification(ip)
        detective_confirms = False
        detective_detail = ""

        if verification:
            payload = verification.get("payload", {})
            detective_confirms = payload.get("threat_level") in ("brute_force", "suspicious")
            failed = payload.get("failed_logins", 0)
            detective_detail = f"{failed} failed login attempts confirmed by Detective" if detective_confirms else "No suspicious login activity found"

        details = alert.get("details", {}) or {}
        intel_result = details.get("threat_intelligence") or None
        anomaly_result = details.get("anomaly_detection") or None

        if intel_result is None and self._threat_intelligence:
            try:
                intel_result = self._threat_intelligence.assess_ip(ip)
            except Exception:
                intel_result = None

        if anomaly_result is None and self._anomaly_detection:
            try:
                flow_features = details.get("flow_features") or {}
                anomaly_features = {
                    "Destination Port": int(flow_features.get("Destination Port", details.get("destination_port", 80))),
                    "Flow Duration": int(flow_features.get("Flow Duration", details.get("flow_duration", 2000))),
                    "Total Fwd Packets": int(flow_features.get("Total Fwd Packets", details.get("total_fwd_packets", 20))),
                    "Total Backward Packets": int(flow_features.get("Total Backward Packets", details.get("total_backward_packets", 12))),
                    "Flow Bytes/s": int(flow_features.get("Flow Bytes/s", details.get("flow_bytes_per_sec", 60000))),
                    "Flow Packets/s": float(flow_features.get("Flow Packets/s", details.get("flow_packets_per_sec", 35.0))),
                }
                anomaly_result = self._anomaly_detection.analyze_flow(anomaly_features, event=threat_type)
            except Exception:
                anomaly_result = None

        # Step 2 — build XAI reasoning
        reasoning, confidence = self._build_reasoning(
            alert, verification, detective_confirms, intel_result, anomaly_result
        )

        # Step 3 — decide action
        action, response_status = self._decide_action(severity, confidence, ip, threat_type)

        # Step 4 — persist response with XAI
        recommendations = self._generate_recommendations(threat_type, severity, action)
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
            "signals": self._build_signals(alert, detective_confirms, detective_detail, intel_result, anomaly_result),
            "recommendations": recommendations,
        }

        execution_status = "not_executed"
        if self._response_automation:
            await self.broadcast_command(AgentName.RESPONSE_AUTOMATION, "execute_response", {
                "action": action,
                "target": ip,
                "status": response_status.value,
            })
            execution = await self._response_automation.execute_action(response)
            execution_status = execution.get("execution_status", "not_executed")
            response["signals"].append(f"[Response Automation] Execution status: {execution_status}")

        if self._forensics:
            await self.broadcast_command(AgentName.FORENSICS, "build_incident_report", {"target": ip})
            report = await self._forensics.create_incident_report(alert, response, intel_result, anomaly_result)
            response["signals"].append(f"[Forensics] {report.get('summary')}")

        await save_response(response)

        await self._log_action(action, ip, confidence)
        self._update_stats(action, confidence)

        # Step 5 — broadcast via WebSocket
        if self._ws_manager:
            await self._ws_manager.broadcast_response(response)

        await self._advance_incident_lifecycle(alert, response, execution_status)

        self.status = "online"
        return response

    async def _set_alert_lifecycle(self, alert_id: str, status: str, lifecycle: Dict[str, Any]) -> None:
        result = await update_incident_alerts_status(alert_id, status, lifecycle)
        updated_alert = result.get("alert")
        if self._ws_manager and updated_alert:
            await self._ws_manager.broadcast_alert(updated_alert)

    async def _advance_incident_lifecycle(self, alert: Dict, response: Dict, execution_status: str) -> None:
        alert_id = alert.get("id")
        if not alert_id:
            return

        target = response.get("target", "unknown")
        response_status = str(response.get("status", "")).lower()

        if response_status == ResponseStatus.MONITORING.value:
            threat_type = str(alert.get("threat_type", "") or "")
            if threat_type == AttackType.BRUTE_FORCE.value:
                auto_block_seconds = self.BRUTE_FORCE_MONITOR_BLOCK_SECONDS
                await self._set_alert_lifecycle(
                    alert_id,
                    "investigating",
                    {
                        "phase": "monitoring",
                        "updated_by": self.NAME.value,
                        "reason": "Brute-force under threshold; auto-block if activity persists",
                        "target": target,
                        "auto_block_seconds": auto_block_seconds,
                    },
                )
                asyncio.create_task(self._auto_block_bruteforce_alert(alert_id, target, auto_block_seconds))
                return

            auto_resolve_seconds = self.MONITORING_AUTO_RESOLVE_SECONDS
            await self._set_alert_lifecycle(
                alert_id,
                "investigating",
                {
                    "phase": "monitoring",
                    "updated_by": self.NAME.value,
                    "reason": "Containment confidence not high enough for immediate block",
                    "target": target,
                    "auto_resolve_seconds": auto_resolve_seconds,
                },
            )
            asyncio.create_task(self._auto_resolve_monitoring_alert(alert_id, target, auto_resolve_seconds))
            return

        if response_status == ResponseStatus.BLOCKED.value and execution_status in ("executed", "already_enforced"):
            auto_unblock_seconds = max(
                int(os.getenv("BLOCK_AUTO_UNBLOCK_SECONDS", "30")),
                self.MIN_RESOLUTION_SECONDS,
            )
            mitigated_count = await mark_attacks_mitigated(
                target,
                {
                    "resolved_by": self.NAME.value,
                    "execution_status": execution_status,
                },
            )

            await self._set_alert_lifecycle(
                alert_id,
                "blocked",
                {
                    "phase": "containment",
                    "updated_by": self.NAME.value,
                    "execution_status": execution_status,
                    "target": target,
                    "mitigated_attacks": mitigated_count,
                    "auto_unblock_seconds": auto_unblock_seconds,
                },
            )
            asyncio.create_task(self._auto_resolve_blocked_alert(alert_id, target, auto_unblock_seconds))
            return

    async def _auto_block_bruteforce_alert(self, alert_id: str, target: str, delay_seconds: int) -> None:
        await asyncio.sleep(delay_seconds)

        latest_alert = await fetch_one("alerts", {"id": alert_id})
        if not latest_alert:
            return

        latest_status = str(latest_alert.get("status", "") or "").lower()
        if latest_status in ("resolved", "blocked"):
            return

        escalation_response = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "action": f"Block IP {target}",
            "target": target,
            "agent": self.NAME.value,
            "confidence": max(0.9, float(latest_alert.get("confidence", 0.0) or 0.0)),
            "reasoning": f"Brute-force activity persisted for {delay_seconds}s in monitoring; escalating to immediate block.",
            "status": ResponseStatus.BLOCKED.value,
            "related_alert_id": alert_id,
            "signals": [
                f"[Commander] Brute-force monitor timer elapsed ({delay_seconds}s)",
                "[Commander] Escalating from monitoring to blocked",
            ],
        }

        execution_status = "not_executed"
        if self._response_automation:
            await self.broadcast_command(AgentName.RESPONSE_AUTOMATION, "execute_response", {
                "action": escalation_response["action"],
                "target": target,
                "status": escalation_response["status"],
            })
            execution = await self._response_automation.execute_action(escalation_response)
            execution_status = execution.get("execution_status", "not_executed")
            escalation_response["signals"].append(f"[Response Automation] Execution status: {execution_status}")

        await save_response(escalation_response)
        if self._ws_manager:
            await self._ws_manager.broadcast_response(escalation_response)

        if execution_status in ("executed", "already_enforced"):
            auto_unblock_seconds = max(
                int(os.getenv("BLOCK_AUTO_UNBLOCK_SECONDS", "30")),
                self.MIN_RESOLUTION_SECONDS,
            )
            mitigated_count = await mark_attacks_mitigated(
                target,
                {
                    "resolved_by": self.NAME.value,
                    "execution_status": execution_status,
                    "reason": "Brute-force monitor escalation",
                },
            )
            await self._set_alert_lifecycle(
                alert_id,
                "blocked",
                {
                    "phase": "containment",
                    "updated_by": self.NAME.value,
                    "execution_status": execution_status,
                    "target": target,
                    "mitigated_attacks": mitigated_count,
                    "auto_unblock_seconds": auto_unblock_seconds,
                    "reason": f"Escalated from monitoring after {delay_seconds}s",
                },
            )
            asyncio.create_task(self._auto_resolve_blocked_alert(alert_id, target, auto_unblock_seconds))

    async def _auto_resolve_monitoring_alert(self, alert_id: str, target: str, delay_seconds: int) -> None:
        await asyncio.sleep(delay_seconds)

        latest_alert = await fetch_one("alerts", {"id": alert_id})
        if not latest_alert:
            return

        latest_status = str(latest_alert.get("status", "")).lower()
        if latest_status in ("resolved", "blocked"):
            return

        updated_count = await resolve_monitoring_responses_for_alert(
            alert_id,
            {
                "updated_by": self.NAME.value,
                "reason": "Monitoring auto-resolve timer elapsed",
            },
        )

        resolution_response = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "action": f"Auto-resolve monitored incident for IP {target}",
            "target": target,
            "agent": self.NAME.value,
            "confidence": 0.6,
            "reasoning": f"No escalation during {delay_seconds}s monitoring window. Incident auto-resolved.",
            "status": ResponseStatus.RESOLVED.value,
            "related_alert_id": alert_id,
            "signals": [
                f"[Commander] Monitoring timer elapsed ({delay_seconds}s)",
                f"[Commander] Converted monitoring responses to resolved: {updated_count}",
                "[Commander] No further escalation observed",
                "[Commander] Incident auto-resolved from monitoring",
            ],
        }
        await save_response(resolution_response)
        if self._ws_manager:
            await self._ws_manager.broadcast_response(resolution_response)

        await self._set_alert_lifecycle(
            alert_id,
            "resolved",
            {
                "phase": "resolved",
                "updated_by": self.NAME.value,
                "resolved_at": datetime.utcnow().isoformat(),
                "resolution": "Monitoring window elapsed without escalation",
                "target": target,
            },
        )

    async def _auto_resolve_blocked_alert(self, alert_id: str, target: str, delay_seconds: int) -> None:
        await asyncio.sleep(delay_seconds)

        latest_alert = await fetch_one("alerts", {"id": alert_id})
        if not latest_alert:
            return

        latest_status = str(latest_alert.get("status", "")).lower()
        if latest_status == "resolved":
            return

        await self._set_alert_lifecycle(
            alert_id,
            "investigating",
            {
                "phase": "resolving",
                "updated_by": self.NAME.value,
                "reason": "Block hold window elapsed; validating containment before closure",
                "target": target,
            },
        )

        updated_count = await resolve_blocked_responses_for_alert(
            alert_id,
            {
                "updated_by": self.NAME.value,
                "reason": "Block hold window elapsed",
            },
        )

        resolution_response = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "action": f"Auto-resolve blocked incident for IP {target}",
            "target": target,
            "agent": self.NAME.value,
            "confidence": 0.7,
            "reasoning": f"Block maintained for {delay_seconds}s without relapse. Incident moved to resolution.",
            "status": ResponseStatus.RESOLVED.value,
            "related_alert_id": alert_id,
            "signals": [
                f"[Commander] Block hold timer elapsed ({delay_seconds}s)",
                f"[Commander] Converted blocked responses to resolved: {updated_count}",
                "[Commander] No renewed malicious activity observed",
                "[Commander] Incident transitioned from blocked to resolving then resolved",
            ],
        }
        await save_response(resolution_response)
        if self._ws_manager:
            await self._ws_manager.broadcast_response(resolution_response)

        await self._set_alert_lifecycle(
            alert_id,
            "resolved",
            {
                "phase": "resolved",
                "updated_by": self.NAME.value,
                "resolved_at": datetime.utcnow().isoformat(),
                "resolution": "Blocked hold window elapsed without relapse",
                "target": target,
            },
        )

    async def reconcile_lifecycle_timeouts(self) -> None:
        """Recover lifecycle timers after reloads by resolving overdue incidents from persisted state."""
        now = datetime.utcnow()

        investigating_alerts = await fetch_recent(
            "alerts",
            limit=200,
            query={"status": "investigating"},
            sort_field="updated_at",
        )
        for alert in investigating_alerts:
            await self._reconcile_investigating_alert(alert, now)

        blocked_alerts = await fetch_recent(
            "alerts",
            limit=200,
            query={"status": "blocked"},
            sort_field="updated_at",
        )
        for alert in blocked_alerts:
            await self._reconcile_blocked_alert(alert, now)

    def _parse_iso(self, value: Any) -> Optional[datetime]:
        if not isinstance(value, str) or not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return None

    async def _run_reconcile_action(self, alert_id: str, action_coro) -> None:
        if not alert_id or alert_id in self._lifecycle_reconcile_inflight:
            return
        self._lifecycle_reconcile_inflight.add(alert_id)
        try:
            await action_coro
        finally:
            self._lifecycle_reconcile_inflight.discard(alert_id)

    async def _reconcile_investigating_alert(self, alert: Dict[str, Any], now: datetime) -> None:
        alert_id = str(alert.get("id") or "")
        lifecycle = alert.get("lifecycle") if isinstance(alert.get("lifecycle"), dict) else {}
        if not lifecycle:
            return

        anchor = self._parse_iso(alert.get("updated_at")) or self._parse_iso(alert.get("timestamp"))
        if not anchor:
            return

        elapsed = (now - anchor).total_seconds()
        target = str(lifecycle.get("target") or alert.get("source_ip") or "unknown")

        auto_block_seconds = lifecycle.get("auto_block_seconds")
        if isinstance(auto_block_seconds, int) and elapsed >= auto_block_seconds:
            await self._run_reconcile_action(alert_id, self._auto_block_bruteforce_alert(alert_id, target, 0))
            return

        auto_resolve_seconds = lifecycle.get("auto_resolve_seconds")
        if isinstance(auto_resolve_seconds, int) and elapsed >= auto_resolve_seconds:
            await self._run_reconcile_action(alert_id, self._auto_resolve_monitoring_alert(alert_id, target, 0))

    async def _reconcile_blocked_alert(self, alert: Dict[str, Any], now: datetime) -> None:
        alert_id = str(alert.get("id") or "")
        lifecycle = alert.get("lifecycle") if isinstance(alert.get("lifecycle"), dict) else {}
        if not lifecycle:
            return

        auto_unblock_seconds = lifecycle.get("auto_unblock_seconds")
        if not isinstance(auto_unblock_seconds, int):
            return

        anchor = self._parse_iso(alert.get("updated_at")) or self._parse_iso(alert.get("timestamp"))
        if not anchor:
            return

        elapsed = (now - anchor).total_seconds()
        if elapsed < auto_unblock_seconds:
            return

        target = str(lifecycle.get("target") or alert.get("source_ip") or "unknown")
        await self._run_reconcile_action(alert_id, self._auto_resolve_blocked_alert(alert_id, target, 0))

    # ------------------------------------------------------------------
    # Explainable AI
    # ------------------------------------------------------------------

    def _build_reasoning(
        self,
        alert: Dict,
        verification: Optional[Dict],
        detective_confirms: bool,
        intel_result: Optional[Dict],
        anomaly_result: Optional[Dict],
    ) -> tuple[str, float]:
        """
        Construct a human-readable reasoning chain and confidence score.
        This is the XAI component.
        """
        parts: List[str] = []
        confidence = max(float(alert.get("confidence", 0.5)), self.CONFIDENCE_BASELINE)

        # Sentry signal
        sentry_event = alert.get("event", "Unknown event")
        parts.append(f"{sentry_event} detected by Sentry Agent from IP {alert.get('source_ip', 'unknown')}")

        # Cross-agent correlation
        if detective_confirms:
            payload = (verification or {}).get("payload", {})
            failed = payload.get("failed_logins", 0)
            parts.append(f"Cross-correlated with {failed} failed login attempts confirmed by Detective Agent")
            confidence = min(0.99, confidence + self.CONFIDENCE_BONUS_DETECTIVE)
        else:
            parts.append("Detective Agent found no corroborating login anomalies")
            confidence = max(0.30, confidence - self.CONFIDENCE_PENALTY_NO_CORROBORATION)

        if intel_result and intel_result.get("matched"):
            parts.append(f"Threat Intelligence matched source to {intel_result.get('label')}")
            confidence = min(
                0.99,
                confidence + min(0.16, float(intel_result.get("confidence", 0.0)) * self.CONFIDENCE_BONUS_INTEL_FACTOR),
            )

        if anomaly_result and anomaly_result.get("prediction") not in (None, "unavailable", "error"):
            parts.append(
                f"Anomaly Detection scored event as {str(anomaly_result.get('prediction')).upper()} at {round(float(anomaly_result.get('score', 0.0)), 2)}"
            )
            if anomaly_result.get("anomaly"):
                confidence = min(0.99, confidence + self.CONFIDENCE_BONUS_ANOMALY)

        # Severity uplift
        sev = alert.get("severity", "medium")
        if sev in ("high", "critical"):
            parts.append(f"Severity classified as {sev.upper()} — immediate response warranted")
            confidence = min(0.99, confidence + self.CONFIDENCE_BONUS_SEVERITY)

        return " → ".join(parts) + ".", round(confidence, 3)

    def _build_signals(
        self,
        alert: Dict,
        detective_confirms: bool,
        detective_detail: str,
        intel_result: Optional[Dict],
        anomaly_result: Optional[Dict],
    ) -> List[str]:
        signals = [f"[Sentry] {alert.get('event', 'Anomaly detected')} from {alert.get('source_ip', 'unknown')}"]
        if detective_confirms:
            signals.append(f"[Detective] {detective_detail}")
        if intel_result and intel_result.get("matched"):
            signals.append(f"[Threat Intelligence] {intel_result.get('label')} ({intel_result.get('source')})")
        if anomaly_result and anomaly_result.get("prediction") not in (None, "unavailable", "error"):
            signals.append(
                f"[Anomaly Detection] {str(anomaly_result.get('prediction')).upper()} score={round(float(anomaly_result.get('score', 0.0)), 3)}"
            )
        signals.append(f"[Commander] Threat severity: {alert.get('severity', 'unknown').upper()}")
        return signals

    def _generate_recommendations(self, threat_type: str, severity: SeverityLevel, action: str) -> List[str]:
        """Generate actionable recommendations based on threat type and severity."""
        recs = []
        if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
            recs.append(f"IMMEDIATE: {action}")

        threat_recs = {
            "brute_force": [
                "Enable account lockout after 5 failed attempts",
                "Implement multi-factor authentication (MFA)",
                "Deploy rate limiting on authentication endpoints",
                "Review and rotate potentially compromised credentials",
            ],
            "port_scan": [
                "Review and minimize exposed services",
                "Update firewall ACLs to restrict unnecessary ports",
                "Enable port scan detection alerts",
                "Consider honeypot deployment for reconnaissance detection",
            ],
            "sql_injection": [
                "Enable parameterized queries on all database endpoints",
                "Deploy WAF rules targeting SQL injection patterns",
                "Audit application input validation routines",
                "Review database user permissions (principle of least privilege)",
            ],
            "xss": [
                "Implement Content Security Policy (CSP) headers",
                "Sanitize all user inputs server-side",
                "Enable HttpOnly and Secure flags on cookies",
                "Deploy XSS filtering in WAF",
            ],
            "ransomware": [
                "Immediately isolate infected hosts from network",
                "Initiate backup restoration procedures",
                "Preserve forensic evidence before remediation",
                "Notify incident response team and management",
            ],
            "ddos": [
                "Enable upstream DDoS mitigation service",
                "Implement rate limiting at edge/CDN level",
                "Scale infrastructure capacity if possible",
                "Activate geo-blocking for suspicious regions",
            ],
            "data_exfiltration": [
                "Block outbound connections to suspicious destinations",
                "Enable Data Loss Prevention (DLP) monitoring",
                "Review user access permissions and recent activity",
                "Preserve network logs for forensic analysis",
            ],
            "mitm": [
                "Force HSTS on all web endpoints",
                "Validate SSL/TLS certificate chains",
                "Enable certificate pinning where possible",
                "Review ARP tables for anomalies",
            ],
            "dns_spoofing": [
                "Enable DNSSEC on all domains",
                "Flush DNS caches on affected systems",
                "Monitor DNS query logs for anomalies",
                "Consider DNS-over-HTTPS (DoH) deployment",
            ],
            "command_control": [
                "Block identified C2 IP addresses at firewall",
                "Run full endpoint forensic scan",
                "Review scheduled tasks and startup items",
                "Isolate potentially compromised hosts",
            ],
            "suspicious_login": [
                "Force password reset for affected account",
                "Verify user identity through secondary channel",
                "Review recent account activity",
                "Enable location-based access controls",
            ],
            "traffic_spike": [
                "Enable rate limiting on affected services",
                "Scale infrastructure capacity",
                "Review traffic patterns for attack indicators",
                "Prepare DDoS mitigation if pattern escalates",
            ],
        }
        recs.extend(threat_recs.get(threat_type, ["Investigate source and review security logs", "Update firewall rules as needed"]))
        return recs

    def _decide_action(
        self, severity: SeverityLevel, confidence: float, ip: str, threat_type: str
    ) -> tuple[str, ResponseStatus]:
        """Map severity + confidence onto a concrete response action."""
        if threat_type == AttackType.DATA_EXFILTRATION.value:
            self._blocked_ips.add(ip)
            return f"Block IP {ip}", ResponseStatus.BLOCKED

        if threat_type == AttackType.PORT_SCAN.value:
            return f"Monitor IP {ip} — reconnaissance watch", ResponseStatus.MONITORING

        if threat_type == AttackType.BRUTE_FORCE.value:
            if confidence >= self.BRUTE_FORCE_BLOCK_CONFIDENCE:
                self._blocked_ips.add(ip)
                return f"Block IP {ip}", ResponseStatus.BLOCKED
            return f"Monitor IP {ip} — brute-force watch", ResponseStatus.MONITORING

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
