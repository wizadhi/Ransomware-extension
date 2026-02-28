import os
import math
import tempfile
import re
import numpy as np
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from dotenv import load_dotenv
load_dotenv()
from feature_extractor import extract_pe_features, is_pe_file
from ml_engine import predict_ml
from signature_engine import signature_detect

app = FastAPI(title="Ransomware Shield API", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── FILE SCAN ENDPOINT ───────────────────────────────────────────

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        content = await file.read()
        tmp.write(content)
        temp_path = tmp.name

    try:
        # Run signature check (local heuristics + VirusTotal + MalwareBazaar)
        sig_result = await signature_detect(temp_path)

        ml_pred = 0
        ml_prob = 0.0
        ml_used = False

        # Only run ML on PE files — model was trained on PE header features
        if is_pe_file(temp_path):
            ml_used = True
            pe_features = extract_pe_features(temp_path)
            ml_pred, ml_prob = predict_ml(pe_features)
        else:
            sig_result["flags"].append("Non-PE file: ML skipped (trained on PE headers only)")

        # Final decision: signature confirmed malicious OR (ML + local heuristics agree)
        sig_pred = sig_result["prediction"]
        if ml_used:
            final_decision = 1 if (sig_result["is_malicious"] or (ml_pred == 1 and sig_result["local_score"] >= 1)) else 0
        else:
            final_decision = sig_pred

        return {
            "filename": file.filename,
            "is_pe_file": ml_used,
            "final_prediction": final_decision,
            "ml": {
                "used": ml_used,
                "prediction": ml_pred,
                "probability": round(ml_prob, 4),
            },
            "signature": {
                "prediction": sig_pred,
                "is_malicious": sig_result["is_malicious"],
                "local_score": sig_result["local_score"],
                "verdict_sources": sig_result["verdict_sources"],
                "flags": sig_result["flags"],
                "hashes": sig_result["hashes"],
            },
            "virustotal": sig_result["virustotal"],
            "malwarebazaar": sig_result["malwarebazaar"],
        }
    finally:
        os.remove(temp_path)


# ─── URL SCAN ENDPOINT ────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str


SUSPICIOUS_URL_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr"}
SUSPICIOUS_KEYWORDS = [
    "ransomware", "decrypt", "bitcoin", "wallet", "crypt",
    "locky", "cerber", "keygen", "crack", "payload"
]
HIGH_RISK_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq"}


@app.post("/scan-url")
async def scan_url(request: URLRequest):
    url = request.url
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path.lower()
    url_lower = url.lower()

    score = 0
    flags = []

    if any(path.endswith(ext) for ext in SUSPICIOUS_URL_EXTENSIONS):
        score += 2
        flags.append("Suspicious executable file extension in URL")

    if any(hostname.endswith(tld) for tld in HIGH_RISK_TLDS):
        score += 2
        flags.append("High-risk TLD")

    if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS):
        score += 3
        flags.append("Ransomware-related keyword in URL")

    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname):
        score += 2
        flags.append("Raw IP address used as hostname")

    # FIX: Removed "URL length > 100" flag — far too common in legit URLs
    # FIX: Raised subdomain threshold from >3 to >4
    if hostname.count(".") > 4:
        score += 1
        flags.append("Excessive subdomains")

    # FIX: Raise threshold from 3 to 4 to reduce false positives
    is_safe = score < 4
    return {
        "url": url,
        "final_prediction": 0 if is_safe else 1,
        "ml_prediction": 0 if is_safe else 1,
        "ml_probability": round(min(score / 10, 1.0), 4),
        "signature_prediction": 1 if score >= 4 else 0,
        "signature_score": min(score, 10),
        "flags": flags,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.1"}
