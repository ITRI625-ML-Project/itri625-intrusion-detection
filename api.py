"""
ITRI625 Project - Intrusion Detection API
==========================================

FastAPI service that loads the artefacts produced by
``../notebooks/IDS_Deep_Learning_Model.ipynb``:

    ../models/ids_mlp_model.keras     - the trained Keras MLP
    ../models/preprocessor.joblib     - the fitted ColumnTransformer
                                         (StandardScaler + OneHotEncoder)
    ../models/feature_schema.joblib   - which columns are numeric/categorical
    ../models/test_metrics.json       - the test-set metrics logged in the notebook

and exposes them as a small REST API. This is the "basic API for the model"
required by rubric item 2.5. The Tkinter desktop app in
``../desktop_app/desktop_app.py`` is the client that talks to this API.

Run it with:
    cd api
    uvicorn api:app --reload --port 8000

Then open http://127.0.0.1:8000/docs for interactive Swagger docs.
"""

import json
import os
from typing import Literal

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "ids_mlp_model.keras")
PREPROCESSOR_PATH = os.path.join(MODEL_DIR, "preprocessor.joblib")
SCHEMA_PATH = os.path.join(MODEL_DIR, "feature_schema.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "test_metrics.json")

DECISION_THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ITRI625 Intrusion Detection API",
    description=(
        "Serves predictions from the trained MLP intrusion-detection model "
        "for the ITRI625 desktop application."
    ),
    version="1.0.0",
)

# Allow the desktop app (or any local client) to call the API without
# running into browser-style CORS issues during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Artefacts are loaded lazily (on first request) and cached in these globals
# so that importing this module never fails just because the notebook
# hasn't been run yet - the API can still start and report a clear error.
_model = None
_preprocessor = None
_schema = None


def _load_artifacts():
    """Load the trained model, preprocessor and schema once, then cache them."""
    global _model, _preprocessor, _schema
    if _model is not None:
        return _model, _preprocessor, _schema

    missing = [
        path
        for path in (MODEL_PATH, PREPROCESSOR_PATH, SCHEMA_PATH)
        if not os.path.exists(path)
    ]
    if missing:
        raise FileNotFoundError(
            "Missing model artefact(s): "
            + ", ".join(missing)
            + ". Run notebooks/IDS_Deep_Learning_Model.ipynb end-to-end first "
              "(it saves these files into ../models)."
        )

    # Imported here so `uvicorn api:app --reload` still starts even before
    # TensorFlow finishes importing / if it's briefly unavailable.
    import tensorflow as tf

    _model = tf.keras.models.load_model(MODEL_PATH)
    _preprocessor = joblib.load(PREPROCESSOR_PATH)
    _schema = joblib.load(SCHEMA_PATH)
    return _model, _preprocessor, _schema


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------
class SessionFeatures(BaseModel):
    """Raw session features, exactly as they appear in the source dataset."""

    network_packet_size: float = Field(..., ge=0, description="Packet size (bytes)")
    protocol_type: Literal["TCP", "UDP", "ICMP"]
    login_attempts: int = Field(..., ge=0)
    session_duration: float = Field(..., ge=0, description="Session length (seconds)")
    encryption_used: Literal["AES", "DES", "None"] = Field(
        "None", description="Use 'None' if no encryption was used"
    )
    ip_reputation_score: float = Field(..., ge=0, le=1)
    failed_logins: int = Field(..., ge=0)
    browser_type: Literal["Chrome", "Edge", "Firefox", "Safari", "Unknown"]
    unusual_time_access: Literal[0, 1]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "network_packet_size": 599,
                "protocol_type": "TCP",
                "login_attempts": 4,
                "session_duration": 492.98,
                "encryption_used": "DES",
                "ip_reputation_score": 0.6068,
                "failed_logins": 1,
                "browser_type": "Edge",
                "unusual_time_access": 0,
            }
        }
    )


class PredictionResponse(BaseModel):
    attack_probability: float
    prediction: int
    label: str
    threshold: float


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    """Simple liveness check the desktop app can poll on startup."""
    artefacts_ready = all(
        os.path.exists(p) for p in (MODEL_PATH, PREPROCESSOR_PATH, SCHEMA_PATH)
    )
    return {"status": "ok", "model_ready": artefacts_ready}


@app.get("/metrics")
def metrics():
    """Return the test-set evaluation metrics logged by the notebook (rubric 2.3),
    so the desktop app can display model performance to the user."""
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(
            status_code=404,
            detail="test_metrics.json not found. Run the notebook first.",
        )
    with open(METRICS_PATH, "r") as f:
        return json.load(f)


@app.post("/predict", response_model=PredictionResponse)
def predict(features: SessionFeatures):
    """Classify a single session as Normal (0) or Attack (1)."""
    try:
        model, preprocessor, _schema = _load_artifacts()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    row = pd.DataFrame([features.model_dump()])
    try:
        X = preprocessor.transform(row)
    except Exception as exc:  # malformed/unseen category, etc.
        raise HTTPException(status_code=400, detail=f"Could not process input: {exc}")

    if hasattr(X, "toarray"):
        X = X.toarray()

    prob = float(model.predict(X, verbose=0).ravel()[0])
    pred = int(prob > DECISION_THRESHOLD)
    label = "Attack" if pred == 1 else "Normal"

    return PredictionResponse(
        attack_probability=prob,
        prediction=pred,
        label=label,
        threshold=DECISION_THRESHOLD,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
