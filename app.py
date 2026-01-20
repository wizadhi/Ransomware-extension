from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile
import uvicorn
import os
from pydantic import BaseModel
from ml_engine import predict_ml
from signature_engine import signature_detect
from feature_schema import validate_features
from feature_extractor import extract_features  # NEW

app = FastAPI(title="Ransomware Detection Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class FeatureInput(BaseModel):
    file_entropy: float
    mass_file_modification: int
    suspicious_extensions: int
    shadow_copy_deletion: int
    crypto_api_usage: int

@app.get("/")
def root():
    return {"status": "Ransomware Detection API is running"}

@app.post("/detect")
def detect_ransomware(data: FeatureInput):
    features = data.dict()

    try:
        validate_features(features)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    feature_vector = list(features.values())

    ml_pred, ml_prob = predict_ml(feature_vector)
    sig_pred, sig_score = signature_detect(features)

    # Hybrid logic (DEFENSIVE)
    final_decision = 1 if (ml_pred == 1 or sig_pred == 1) else 0

    return {
        "ml_prediction": ml_pred,
        "ml_probability": round(ml_prob, 4),
        "signature_prediction": sig_pred,
        "signature_score": sig_score,
        "final_decision": final_decision
    }

@app.post("/predict")
def predict(data: FeatureInput):
    features = data.dict()

    try:
        validate_features(features)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    feature_vector = list(features.values())

    # ML Prediction
    ml_pred, ml_prob = predict_ml(feature_vector)

    # Signature-based Detection
    sig_pred, sig_score = signature_detect(features)

    # Hybrid Decision (Defensive)
    final_decision = 1 if (ml_pred == 1 or sig_pred == 1) else 0

    return {
        "ml_prediction": int(ml_pred),
        "ml_probability": round(float(ml_prob), 4),
        "signature_prediction": int(sig_pred),
        "signature_score": sig_score,
        "final_decision": final_decision
    }

@app.post("/scan-file")
async def scan_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")

    # Save temporarily
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        content = await file.read()
        temp.write(content)
        temp_path = temp.name

    try:
        features = extract_features(temp_path)
        validate_features(features)

        feature_vector = list(features.values())
        ml_pred, ml_prob = predict_ml(feature_vector)
        sig_pred, sig_score = signature_detect(features)

        final_decision = 1 if (ml_pred or sig_pred) else 0

        return {
            "filename": file.filename,
            "ml_prediction": ml_pred,
            "ml_probability": round(ml_prob, 4),
            "signature_prediction": sig_pred,
            "signature_score": sig_score,
            "final_decision": final_decision
        }

    finally:
        os.remove(temp_path)

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=True)
