"""Anomaly Detection Agent — operational wrapper around ML anomaly scoring."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ml.predictor import predict_anomaly


class AnomalyDetectionAgent:
    NAME = "Anomaly Detection"
    ROLE = "Behavioral Analytics"
    RESPONSIBILITIES = [
        "Detect behavioral anomalies in traffic and requests",
        "Score suspicious events with ML models",
        "Identify unknown or zero-day-like patterns",
        "Provide anomaly confidence for downstream response",
    ]

    def __init__(self):
        self.status = "online"
        self.threat_count = 0
        self.last_action: Optional[str] = None
        self.last_action_time: Optional[datetime] = None
        self.confidence_scores: List[float] = []
        self.start_time = datetime.utcnow()

    def analyze_flow(self, features: Dict[str, Any], event: str = "anomaly_check") -> Dict[str, Any]:
        self.status = "busy"
        result = predict_anomaly(features)
        score = float(result.get("score", 0.0))
        self._update_stats(f"{event}: {result.get('prediction', 'unknown')}", score)
        self.status = "online"
        return result

    def _update_stats(self, action: str, confidence: float):
        if confidence >= 0.5:
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
