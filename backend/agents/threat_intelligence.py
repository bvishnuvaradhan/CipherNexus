"""Threat Intelligence Agent — correlates IPs with known threat indicators."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


class ThreatIntelligenceAgent:
    NAME = "Threat Intelligence"
    ROLE = "Threat Intelligence"
    RESPONSIBILITIES = [
        "Monitor IOC and reputation feeds",
        "Correlate IPs with known malicious infrastructure",
        "Track CVE and threat reputation context",
        "Reduce false positives with external intel",
    ]

    IOC_DB = {
        "185.220.101.15": {
            "label": "Known botnet/TOR relay node",
            "confidence": 0.94,
            "source": "reputation_feed",
        },
        "205.174.165.73": {
            "label": "Known attack-simulation source from CIC-IDS dataset",
            "confidence": 0.97,
            "source": "dataset_ioc_feed",
        },
        "205.174.165.69": {
            "label": "Known DDoS participant node",
            "confidence": 0.89,
            "source": "botnet_feed",
        },
        "205.174.165.70": {
            "label": "Known DDoS participant node",
            "confidence": 0.89,
            "source": "botnet_feed",
        },
        "205.174.165.71": {
            "label": "Known DDoS participant node",
            "confidence": 0.89,
            "source": "botnet_feed",
        },
    }

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self.start_time = datetime.utcnow()

    def assess_ip(self, ip: Optional[str]) -> Dict[str, Any]:
        if not ip:
            return {"matched": False, "confidence": 0.0, "label": None, "source": None}

        match = self.IOC_DB.get(ip)
        if match:
            confidence = float(match["confidence"])
            self._update_stats(f"IOC match for {ip}", confidence)
            return {
                "matched": True,
                "ip": ip,
                "confidence": confidence,
                "label": match["label"],
                "source": match["source"],
            }

        if ip.startswith("185.220.101."):
            confidence = 0.82
            self._update_stats(f"TOR reputation match for {ip}", confidence)
            return {
                "matched": True,
                "ip": ip,
                "confidence": confidence,
                "label": "TOR / anonymization network range",
                "source": "reputation_range_rule",
            }

        return {"matched": False, "ip": ip, "confidence": 0.0, "label": None, "source": None}

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
