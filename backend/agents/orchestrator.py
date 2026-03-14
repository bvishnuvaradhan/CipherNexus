"""
Agent Orchestrator
Bootstraps all agents, wires up the A2A message bus,
and runs the continuous monitoring / message-processing loops.
"""

from __future__ import annotations
import asyncio
from typing import Optional

from agents.sentry import SentryAgent
from agents.detective import DetectiveAgent
from agents.commander import CommanderAgent


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
        self._bus: asyncio.Queue = asyncio.Queue()
        self._ws_manager: Optional[object] = None
        self._running = False

    async def initialize(self):
        """Wire up agents and inject shared dependencies."""
        # Attach the A2A message bus
        self.sentry.attach_bus(self._bus)
        self.detective.attach_bus(self._bus)
        self.commander.attach_bus(self._bus)

        # Give Commander a direct handle to Detective for sync queries
        self.commander.attach_detective(self.detective)

        print("[ONLINE] Sentry Agent")
        print("[ONLINE] Detective Agent")
        print("[ONLINE] Commander Agent")

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
            self._process_message_bus(),
            self._push_live_events(),
        )

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
            # Build a minimal alert dict for Commander
            alert = {
                "id": msg.get("id"),
                "event": event,
                "threat_type": event,
                "severity": msg.get("severity", "medium"),
                "source_ip": msg.get("ip"),
                "confidence": msg.get("payload", {}).get("confidence", 0.70),
            }
            await self.commander.process_alert(alert)

    async def _push_live_events(self):
        """
        Periodically broadcast system status (threat level, agent status)
        to all connected WebSocket clients.
        """
        from database.repository import get_threat_level

        while True:
            await asyncio.sleep(10)
            if self._ws_manager:
                try:
                    threat = await get_threat_level()
                    await self._ws_manager.broadcast_threat_level(threat)
                    status = {
                        "agents": [
                            self.sentry.get_status(),
                            self.detective.get_status(),
                            self.commander.get_status(),
                        ]
                    }
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
                    {"failed_attempts": len(alerts), "simulated": True},
                )
            return {"triggered": "Detective", "alerts": len(alerts)}

        elif attack_type == AttackType.PORT_SCAN.value:
            ports = random.sample(range(1, 65535), random.randint(50, 500))
            alert = await self.sentry.detect_port_scan(ip, ports)
            if alert:
                await self.sentry.report_to_commander(
                    "port_scan", ip, SeverityLevel(alert["severity"]),
                    {"ports_count": len(ports), "simulated": True},
                )
            return {"triggered": "Sentry", "alert": alert}

        elif attack_type == AttackType.SUSPICIOUS_LOGIN.value:
            from agents.detective import DetectiveAgent
            location = random.choice(DetectiveAgent.SUSPICIOUS_LOCATIONS)
            alert = await self.detective.analyze_login_location(ip, "admin", location)
            if alert:
                await self.detective.report_to_commander(
                    "suspicious_login", ip, SeverityLevel(alert["severity"]),
                    {"location": location, "simulated": True},
                )
            return {"triggered": "Detective", "alert": alert}

        elif attack_type == AttackType.DATA_EXFILTRATION.value:
            size = random.randint(80 * 1024 * 1024, 400 * 1024 * 1024)
            alert = await self.detective.analyze_data_exfiltration(ip, size)
            if alert:
                await self.detective.report_to_commander(
                    "data_exfiltration", ip, SeverityLevel(alert["severity"]),
                    {"megabytes": round(size / 1024 / 1024, 1), "simulated": True},
                )
            return {"triggered": "Detective", "alert": alert}

        elif attack_type == AttackType.TRAFFIC_SPIKE.value:
            rate = random.randint(2000, 8000)
            alert = await self.sentry.detect_traffic_spike(ip, rate)
            if alert:
                await self.sentry.report_to_commander(
                    "traffic_spike", ip, SeverityLevel(alert["severity"]),
                    {"packet_rate": rate, "simulated": True},
                )
            return {"triggered": "Sentry", "alert": alert}

        return {"triggered": "none", "reason": "unknown attack type"}
