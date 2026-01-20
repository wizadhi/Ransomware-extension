def validate_features(features: dict):
    required_keys = [
        "file_entropy",
        "mass_file_modification",
        "suspicious_extensions",
        "shadow_copy_deletion",
        "crypto_api_usage"
    ]

    for key in required_keys:
        if key not in features:
            raise ValueError(f"Missing feature: {key}")

        if not isinstance(features[key], (int, float)):
            raise ValueError(f"Invalid type for {key}")

    return True
