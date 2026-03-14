"""ML inference endpoints powered by trained dataset models."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ml.predictor import model_status, predict_anomaly

router = APIRouter()


class PredictRequest(BaseModel):
    features: Dict[str, Any] = Field(default_factory=dict)


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
