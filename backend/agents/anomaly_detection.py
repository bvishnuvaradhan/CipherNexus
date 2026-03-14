"""Anomaly Detection Agent — operational wrapper around ML anomaly scoring."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ml.predictor import predict_anomaly


def heuristic_sparse_score(features: Dict[str, Any], event: str) -> float:
    destination_port = int(features.get("Destination Port", 0) or 0)
    flow_duration = int(features.get("Flow Duration", 0) or 0)
    forward_packets = int(features.get("Total Fwd Packets", 0) or 0)
    backward_packets = int(features.get("Total Backward Packets", 0) or 0)
    bytes_per_second = float(features.get("Flow Bytes/s", 0) or 0)
    packets_per_second = float(features.get("Flow Packets/s", 0) or 0)

    score = 0.18
    if packets_per_second >= 5000:
        score += 0.34
    elif packets_per_second >= 500:
        score += 0.22
    elif packets_per_second >= 120:
        score += 0.12

    if bytes_per_second >= 1_000_000:
        score += 0.28
    elif bytes_per_second >= 250_000:
        score += 0.18
    elif bytes_per_second >= 100_000:
        score += 0.10

    if forward_packets >= 1000:
        score += 0.18
    elif forward_packets >= 200:
        score += 0.10

    if backward_packets <= 10 and forward_packets >= 100:
        score += 0.08

    if flow_duration >= 30_000:
        score += 0.12
    elif flow_duration >= 8_000:
        score += 0.06

    event_floor = {
        "ddos": 0.88,
        "command_control": 0.84,
        "ransomware": 0.82,
        "data_exfiltration": 0.74,
        "port_scan": 0.68,
        "traffic_spike": 0.66,
        "brute_force": 0.62,
        "suspicious_login": 0.58,
        "sql_injection": 0.64,
        "xss": 0.58,
        "mitm": 0.72,
        "dns_spoofing": 0.68,
    }

    if destination_port in {22, 3389} and event in {"brute_force", "suspicious_login", "port_scan"}:
        score += 0.06
    if destination_port == 443 and event in {"data_exfiltration", "command_control"}:
        score += 0.06

    floor = event_floor.get(event, 0.0)
    if score >= max(0.5, floor - 0.08):
        score = max(score, floor)

    return min(0.99, round(score, 3))


def evaluate_flow(features: Dict[str, Any], event: str = "anomaly_check") -> Dict[str, Any]:
    result = predict_anomaly(features)
    provided_feature_count = int(result.get("provided_feature_count", len(features)))
    if provided_feature_count >= 10:
        result["analysis_source"] = "ml_model"
        return result

    heuristic_score = heuristic_sparse_score(features, event)
    if heuristic_score <= float(result.get("score", 0.0)):
        result["analysis_source"] = "ml_model"
        return result

    threshold = float(result.get("threshold", 0.5))
    hybrid_result = dict(result)
    hybrid_result["score"] = round(heuristic_score, 3)
    hybrid_result["anomaly"] = heuristic_score >= threshold
    hybrid_result["prediction"] = "anomaly" if hybrid_result["anomaly"] else "normal"
    hybrid_result["analysis_source"] = "hybrid_sparse_flow"
    return hybrid_result


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
        result = evaluate_flow(features, event=event)
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
