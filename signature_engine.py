"""
signature_engine.py — Signature-based ransomware detection
Combines local heuristics + VirusTotal API + MalwareBazaar API
"""

import hashlib
import math
import os
import httpx

# ─── CONFIG ───────────────────────────────────────────────────────
# Set these in your environment or .env file
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"

# Minimum number of VT engines that must flag a file to consider it malicious
VT_DETECTION_THRESHOLD = 5

# ─── LOCAL HEURISTICS ─────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs"}


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _compute_hashes(file_path: str) -> dict:
    """Return MD5, SHA1, SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _local_heuristics(file_path: str) -> tuple[int, list[str]]:
    """Local entropy + extension checks. Returns (score, flags)."""
    score = 0
    flags = []

    ext = os.path.splitext(file_path)[1].lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        score += 1
        flags.append(f"Suspicious executable extension: {ext}")

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        entropy = _calculate_entropy(data)
        if entropy > 7.5:
            score += 1
            flags.append(f"High entropy: {entropy:.2f} (possible encryption/packing)")
    except Exception:
        pass

    return score, flags


# ─── VIRUSTOTAL ───────────────────────────────────────────────────

async def _check_virustotal(sha256: str) -> dict:
    """
    Query VirusTotal for a file hash.
    Returns a result dict with detection stats.
    Docs: https://developers.virustotal.com/reference/file-info
    """
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY not set"}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"{VIRUSTOTAL_API_URL}{sha256}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code == 404:
            return {
                "available": True,
                "found": False,
                "message": "Hash not found in VirusTotal database",
            }

        if resp.status_code == 401:
            return {"available": False, "reason": "Invalid VirusTotal API key"}

        if resp.status_code != 200:
            return {"available": False, "reason": f"VirusTotal returned HTTP {resp.status_code}"}

        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        detected = malicious + suspicious

        # Pull top engine names that flagged it
        engines = data["data"]["attributes"].get("last_analysis_results", {})
        flagged_by = [
            name for name, result in engines.items()
            if result.get("category") in ("malicious", "suspicious")
        ][:10]  # cap at 10 for readability

        return {
            "available": True,
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "detected": detected,
            "is_malicious": malicious >= VT_DETECTION_THRESHOLD,
            "flagged_by": flagged_by,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    except httpx.TimeoutException:
        return {"available": False, "reason": "VirusTotal request timed out"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ─── MALWAREBAZAAR ────────────────────────────────────────────────

async def _check_malwarebazaar(sha256: str) -> dict:
    """
    Query MalwareBazaar (abuse.ch) for a file hash.
    No API key required — free public API.
    Docs: https://bazaar.abuse.ch/api/
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                MALWAREBAZAAR_API_URL,
                data={"query": "get_info", "hash": sha256},
            )

        if resp.status_code != 200:
            return {"available": False, "reason": f"MalwareBazaar returned HTTP {resp.status_code}"}

        data = resp.json()

        if data.get("query_status") == "hash_not_found":
            return {
                "available": True,
                "found": False,
                "message": "Hash not found in MalwareBazaar database",
            }

        if data.get("query_status") != "ok":
            return {"available": False, "reason": f"MalwareBazaar status: {data.get('query_status')}"}

        info = data["data"][0]
        return {
            "available": True,
            "found": True,
            "is_malicious": True,  # if found in MalwareBazaar, it's confirmed malware
            "file_name": info.get("file_name"),
            "file_type": info.get("file_type"),
            "malware_family": info.get("tags", []),
            "reporter": info.get("reporter"),
            "first_seen": info.get("first_seen"),
            "signature": info.get("signature"),
            "permalink": f"https://bazaar.abuse.ch/sample/{sha256}/",
        }

    except httpx.TimeoutException:
        return {"available": False, "reason": "MalwareBazaar request timed out"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


# ─── MAIN SIGNATURE DETECT ────────────────────────────────────────

async def signature_detect(file_path: str) -> dict:
    """
    Full signature check combining:
      1. Local heuristics (entropy + extension)
      2. VirusTotal hash lookup
      3. MalwareBazaar hash lookup

    Returns a unified result dict.
    """
    hashes = _compute_hashes(file_path)
    local_score, local_flags = _local_heuristics(file_path)

    # Run both API checks concurrently
    import asyncio
    vt_result, mb_result = await asyncio.gather(
        _check_virustotal(hashes["sha256"]),
        _check_malwarebazaar(hashes["sha256"]),
    )

    # ─── Combine into final verdict ───────────────────────────────
    is_malicious = False
    flags = list(local_flags)
    verdict_sources = []

    # VirusTotal verdict
    if vt_result.get("available") and vt_result.get("found"):
        if vt_result.get("is_malicious"):
            is_malicious = True
            flags.append(
                f"VirusTotal: {vt_result['malicious']} engines detected as malicious "
                f"({vt_result['detected']}/{vt_result['total_engines']} total detections)"
            )
            verdict_sources.append("VirusTotal")
        elif vt_result.get("detected", 0) > 0:
            flags.append(
                f"VirusTotal: low detections ({vt_result['detected']}/{vt_result['total_engines']}) — monitor"
            )

    # MalwareBazaar verdict
    if mb_result.get("available") and mb_result.get("found"):
        is_malicious = True
        family = ", ".join(mb_result.get("malware_family") or []) or "unknown"
        flags.append(
            f"MalwareBazaar: confirmed malware — family: {family}, "
            f"first seen: {mb_result.get('first_seen', 'unknown')}"
        )
        verdict_sources.append("MalwareBazaar")

    # Fall back to local heuristics only if APIs unavailable
    if not vt_result.get("available") and not mb_result.get("available"):
        if local_score >= 2:
            is_malicious = True
            verdict_sources.append("local heuristics (APIs unavailable)")

    return {
        "prediction": 1 if is_malicious else 0,
        "is_malicious": is_malicious,
        "verdict_sources": verdict_sources,
        "local_score": local_score,
        "flags": flags,
        "hashes": hashes,
        "virustotal": vt_result,
        "malwarebazaar": mb_result,
    }
