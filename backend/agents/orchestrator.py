"""
Agent Orchestrator
Bootstraps all agents, wires up the A2A message bus,
and runs the continuous monitoring / message-processing loops.
"""

from __future__ import annotations
import asyncio
import random
from typing import Optional

from agents.sentry import SentryAgent
from agents.detective import DetectiveAgent
from agents.commander import CommanderAgent
from agents.threat_intelligence import ThreatIntelligenceAgent
from agents.anomaly_detection import AnomalyDetectionAgent
from agents.response_automation import ResponseAutomationAgent
from agents.forensics import ForensicsAgent


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

    async def initialize(self):
        self.sentry.attach_bus(self._bus)
        self.detective.attach_bus(self._bus)
        self.commander.attach_bus(self._bus)
        self.response_automation.attach_bus(self._bus)
        self.forensics.attach_bus(self._bus)
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

    async def run_core_services(self):
        """Run core message bus and event pushing services."""
        self._running = True
        await asyncio.gather(
            self._process_message_bus(),
            self._push_live_events(),
        )

    async def run_continuous_monitoring(self):
        """Run continuous monitoring with threat generation (optional)."""
        self._running = True
        await asyncio.gather(
            # Disabled automatic threat generation - threats only come from Hacker Console
            # self.sentry.monitor_loop(interval=15.0),
            # self.detective.monitor_loop(interval=12.0),
            self._process_message_bus(),
            self._push_live_events(),
        )

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
            # Use alert_id from payload if provided, otherwise use message id
            payload = msg.get("payload", {})
            alert_id = payload.get("alert_id") or msg.get("id")
            alert = {
                "id": alert_id,
                "event": event,
                "threat_type": event,
                "severity": msg.get("severity", "medium"),
                "source_ip": msg.get("ip"),
                "confidence": payload.get("confidence", 0.70),
                "details": payload,  # Pass full payload as details for Commander
            }
            await self.commander.process_alert(alert)

    async def _push_live_events(self):
        from database.repository import get_threat_level

        while True:
            await asyncio.sleep(10)
            try:
                await self.commander.reconcile_lifecycle_timeouts()
            except Exception as e:
                print(f"[WARN] Lifecycle reconciliation error: {e}")
            if self._ws_manager:
                try:
                    threat = await get_threat_level()
                    await self._ws_manager.broadcast_threat_level(threat)
                    status = {
                        "agents": [
                            self.sentry.get_status(),
                            self.detective.get_status(),
                            self.commander.get_status(),
                            self.threat_intelligence.get_status(),
                            self.anomaly_detection.get_status(),
                            self.response_automation.get_status(),
                            self.forensics.get_status(),
                        ]
                    }
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
        context: dict = None,
    ) -> dict:
        """
        Trigger a simulation from the Hacker Console.
        Routes to the appropriate agent based on attack type.
        """
        from models.schemas import AttackType, SeverityLevel

        params = params or {}
        context = context or {}
        flow_features = context.get("flow_features") or {}

        def build_details(extra: dict | None = None) -> dict:
            details = dict(extra or {})
            if flow_features:
                details["flow_features"] = flow_features
            return details
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
                last_alert = alerts[-1]
                # Call Commander directly (synchronous) instead of message bus
                commander_response = await self.commander.process_alert({
                    "id": last_alert.get("id"),
                    "event": "brute_force_detected",
                    "threat_type": "brute_force",
                    "severity": last_alert.get("severity", "high"),
                    "source_ip": ip,
                    "confidence": last_alert.get("confidence", 0.85),
                    "details": build_details({"failed_attempts": len(alerts), "username": username}),
                })
            return {"triggered": "Detective", "alert": alerts[-1] if alerts else None, "alerts_count": len(alerts), "username": username}

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
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "port_scan",
                    "threat_type": "port_scan",
                    "severity": alert.get("severity", "medium"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.75),
                    "details": build_details({"ports_count": len(ports), "range": f"{start}-{end}"}),
                })
            return {"triggered": "Sentry", "alert": alert, "ports_scanned": len(ports)}

        # ── Suspicious Login ───────────────────────────────────────────
        elif attack_type == AttackType.SUSPICIOUS_LOGIN.value:
            username = params.get("username", "admin")
            device_fingerprint = params.get("device_fingerprint", "unknown_device")
            location = random.choice(DetectiveAgent.SUSPICIOUS_LOCATIONS)
            alert = await self.detective.analyze_login_location(ip, username, location, device_fingerprint)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "suspicious_login",
                    "threat_type": "suspicious_login",
                    "severity": alert.get("severity", "medium"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.80),
                    "details": build_details({"location": location, "username": username}),
                })
            return {"triggered": "Detective", "alert": alert, "location": location}

        # ── Data Exfiltration ──────────────────────────────────────────
        elif attack_type == AttackType.DATA_EXFILTRATION.value:
            mb = params.get("payload_size_mb") or random.randint(80, 400)
            size = mb * 1024 * 1024
            exfil_protocol = params.get("exfil_protocol")
            destination_type = params.get("destination_type")
            exfil_encryption = params.get("exfil_encryption", "none")
            alert = await self.detective.analyze_data_exfiltration(ip, size, exfil_protocol, destination_type, exfil_encryption)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "data_exfiltration",
                    "threat_type": "data_exfiltration",
                    "severity": alert.get("severity", "critical"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.90),
                    "details": build_details({"megabytes": mb, "protocol": exfil_protocol}),
                })
            return {"triggered": "Detective", "alert": alert, "megabytes": mb}

        # ── Traffic Spike ──────────────────────────────────────────────
        elif attack_type == AttackType.TRAFFIC_SPIKE.value:
            rate = params.get("packet_rate") or random.randint(2000, 8000)
            spike_protocol = params.get("spike_protocol", "tcp")
            source_spoofing = params.get("source_spoofing", False)
            alert = await self.sentry.detect_traffic_spike(ip, rate, spike_protocol, source_spoofing)
            if alert:
                await self.commander.process_alert({
                    "id": alert.get("id"),
                    "event": "traffic_spike",
                    "threat_type": "traffic_spike",
                    "severity": alert.get("severity", "high"),
                    "source_ip": ip,
                    "confidence": alert.get("confidence", 0.85),
                    "details": build_details({"packet_rate": rate}),
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
                    "details": build_details({"packet_rate": rate, "concurrent_connections": conns}),
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
                    "details": build_details({"injection_type": injection_type, "endpoint": endpoint}),
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
                    "details": build_details({"xss_type": xss_type, "endpoint": endpoint}),
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
                    "details": build_details({"spread_rate": spread_rate, "family": ransom_family}),
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
                    "details": build_details({"target_protocol": protocol, "technique": mitm_technique}),
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
                    "details": build_details({"target_domain": domain}),
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
                    "details": build_details({"beacon_interval": interval, "protocol": c2_protocol}),
                })
            return {"triggered": "Sentry", "alert": alert, "beacon_interval": interval}

        return {"triggered": "none", "reason": "unknown attack type"}
