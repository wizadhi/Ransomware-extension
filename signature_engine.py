# Simple signature-based ransomware detection

RANSOMWARE_INDICATORS = {
    "file_entropy": 7.5,
    "mass_file_modification": 100,
    "suspicious_extensions": 1,
    "shadow_copy_deletion": 1,
    "crypto_api_usage": 1
}


def signature_detect(features: dict):
    score = 0

    if features["file_entropy"] >= RANSOMWARE_INDICATORS["file_entropy"]:
        score += 1

    if features["mass_file_modification"] >= RANSOMWARE_INDICATORS["mass_file_modification"]:
        score += 1

    if features["suspicious_extensions"]:
        score += 1

    if features["shadow_copy_deletion"]:
        score += 1

    if features["crypto_api_usage"]:
        score += 1

    # Threshold-based decision
    if score >= 3:
        return 1, score   # ransomware

    return 0, score
