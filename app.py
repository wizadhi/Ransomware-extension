import os
import math
import tempfile
import re
import numpy as np
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse

from feature_extractor import extract_pe_features, extract_simple_features, is_pe_file, calculate_entropy
from ml_engine import predict_ml, load_model

app = FastAPI(title="Ransomware Shield API", version="2.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── SIGNATURE-BASED DETECTION ────────────────────────────────────

# FIX: Tightened - requires MULTIPLE strong signals, not just entropy alone
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs"}

def signature_detect(file_path: str):
    score = 0
    flags = []

    ext = os.path.splitext(file_path)[1].lower()

    # Only flag extension if it's truly executable (not .js, .zip which are common/benign)
    if ext in SUSPICIOUS_EXTENSIONS:
        score += 1
        flags.append(f"Suspicious executable extension: {ext}")

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        entropy = -sum(
            (c / len(data)) * math.log2(c / len(data))
            for c in (data.count(bytes([b])) for b in range(256))
            if c > 0
        ) if data else 0.0

        # FIX: Raise entropy threshold to 7.5 (was 7.2) — reduces false positives
        # from compressed/minified legit files
        if entropy > 7.5:
            score += 1
            flags.append(f"High entropy: {entropy:.2f}")
    except Exception:
        pass

    # FIX: Require score >= 2 (was 1 effectively via OR with ML)
    prediction = 1 if score >= 2 else 0
    return prediction, score, flags


# ─── FILE SCAN ENDPOINT ───────────────────────────────────────────

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
        content = await file.read()
        tmp.write(content)
        temp_path = tmp.name

    try:
        sig_pred, sig_score, sig_flags = signature_detect(temp_path)

        ml_pred = 0
        ml_prob = 0.0
        ml_used = False

        # FIX: Only run ML on PE files — it was trained on PE header features
        if is_pe_file(temp_path):
            ml_used = True
            pe_features = extract_pe_features(temp_path)
            ml_pred, ml_prob = predict_ml(pe_features)
        else:
            sig_flags.append("Non-PE file: ML skipped (trained on PE headers only)")

        # FIX: Use AND logic for final decision — require BOTH ML and signature
        # to agree before flagging as ransomware (reduces false positives)
        if ml_used:
            final_decision = 1 if (ml_pred == 1 and sig_pred == 1) else 0
        else:
            # For non-PE files, rely solely on signature with higher bar
            final_decision = 1 if sig_score >= 2 else 0

        return {
            "filename": file.filename,
            "is_pe_file": ml_used,
            "ml_prediction": ml_pred,
            "ml_probability": round(ml_prob, 4),
            "ml_used": ml_used,
            "signature_prediction": sig_pred,
            "signature_score": sig_score,
            "signature_flags": sig_flags,
            "final_prediction": final_decision,
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
