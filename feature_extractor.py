import math
import os

def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)

    return round(entropy, 2)


def extract_features(file_path):
    entropy = calculate_entropy(file_path)

    suspicious_extensions = int(
        os.path.splitext(file_path)[1].lower() in [".exe", ".dll", ".bat", ".ps1"]
    )

    # These are simulated (static analysis limitation)
    mass_file_modification = 0
    shadow_copy_deletion = 0
    crypto_api_usage = int(entropy > 7.2)

    return {
        "file_entropy": entropy,
        "mass_file_modification": mass_file_modification,
        "suspicious_extensions": suspicious_extensions,
        "shadow_copy_deletion": shadow_copy_deletion,
        "crypto_api_usage": crypto_api_usage
    }
