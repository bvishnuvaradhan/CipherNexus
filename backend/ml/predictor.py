"""Model loading and inference helpers for IDS predictions."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd


MODEL_PATH = Path(__file__).resolve().parents[1] / "training_artifacts" / "supervised_binary_sgd.joblib"


@lru_cache(maxsize=1)
def load_supervised_model(model_path: str | None = None):
    """Load and cache the trained supervised binary model."""
    path = Path(model_path) if model_path else MODEL_PATH
    if not path.exists():
        raise FileNotFoundError(
            f"Model not found at {path}. Train first with: python ml/train_cicids.py --dataset-dir ../dataset"
        )
    return joblib.load(path)


def _expected_features(model) -> List[str]:
    """Extract expected feature names from fitted preprocessing step."""
    try:
        imputer = model.named_steps["imputer"]
        names = list(getattr(imputer, "feature_names_in_", []))
        if names:
            return names
    except Exception:
        pass
    raise RuntimeError("Unable to infer model feature names from the trained pipeline.")


def _prepare_frame(features: Dict[str, Any], expected_features: List[str]) -> pd.DataFrame:
    """Build a single-row dataframe aligned to the model's expected feature schema."""
    row = {name: np.nan for name in expected_features}
    for key, value in features.items():
        if key in row:
            row[key] = pd.to_numeric(value, errors="coerce")

    return pd.DataFrame([row], columns=expected_features)


def predict_anomaly(features: Dict[str, Any]) -> Dict[str, Any]:
    """Run anomaly prediction using the supervised binary model."""
    model = load_supervised_model()
    expected = _expected_features(model)
    frame = _prepare_frame(features, expected)

    pred = int(model.predict(frame)[0])
    if hasattr(model, "predict_proba"):
        score = float(model.predict_proba(frame)[0][1])
    else:
        decision = float(model.decision_function(frame)[0])
        score = float(1.0 / (1.0 + np.exp(-decision)))

    label = "anomaly" if pred == 1 else "normal"
    return {
        "prediction": label,
        "anomaly": bool(pred == 1),
        "score": score,
        "threshold": 0.5,
        "expected_feature_count": len(expected),
        "provided_feature_count": len(features),
    }


def model_status() -> Dict[str, Any]:
    """Return model availability and metadata for diagnostics."""
    path = MODEL_PATH
    exists = path.exists()
    status: Dict[str, Any] = {
        "model_path": str(path),
        "model_exists": exists,
    }
    if exists:
        model = load_supervised_model()
        status["expected_feature_count"] = len(_expected_features(model))
    return status
