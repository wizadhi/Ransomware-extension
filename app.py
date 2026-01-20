from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from ml_engine import predict_ml
from signature_engine import signature_detect
from feature_schema import validate_features

app = FastAPI(title="Ransomware Detection Engine")


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

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=True)
