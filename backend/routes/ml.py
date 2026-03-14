"""ML inference endpoints powered by trained dataset models."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ml.predictor import (
    get_anomaly_threshold,
    model_status,
    predict_anomaly,
    set_anomaly_threshold,
)

router = APIRouter()


class PredictRequest(BaseModel):
    features: Dict[str, Any] = Field(default_factory=dict)


class MlConfigRequest(BaseModel):
    anomaly_threshold: float = Field(default=0.5, ge=0.0, le=1.0)


@router.get("/status")
async def ml_status():
    try:
        return model_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/predict")
async def ml_predict(payload: PredictRequest):
    if not payload.features:
        raise HTTPException(status_code=400, detail="features payload is required")

    try:
        result = predict_anomaly(payload.features)
        return {
            "message": "Prediction completed",
            "result": result,
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/config")
async def ml_config_get():
    return {
        "anomaly_threshold": get_anomaly_threshold(),
    }


@router.post("/config")
async def ml_config_set(payload: MlConfigRequest):
    value = set_anomaly_threshold(payload.anomaly_threshold)
    return {
        "message": "ML config updated",
        "anomaly_threshold": value,
    }
