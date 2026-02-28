import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(BASE_DIR, "Dataset", "data_file.csv")
MODEL_PATH = os.path.join(BASE_DIR, "ransomware_ml_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
FEATURE_COLS_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")

# FIX: Correct label column name (was "label", dataset uses "Benign")
LABEL_COLUMN = "Benign"

# The 15 PE-header features the model is trained on
PE_FEATURE_COLUMNS = [
    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
    "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
    "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
    "BitcoinAddresses"
]


def train_model():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found at: {DATASET_PATH}\n"
            "Please ensure data_file.csv exists in the Dataset/ folder."
        )

    print(f"[+] Loading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"[+] Dataset shape: {df.shape}")

    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"Column '{LABEL_COLUMN}' not found. Columns: {list(df.columns)}")

    X = df[PE_FEATURE_COLUMNS]
    # FIX: Invert label — dataset Benign=1 means safe; we want ransomware=1
    y = 1 - df[LABEL_COLUMN]

    print(f"[+] Class distribution:\n{y.value_counts()}")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # FIX: class_weight='balanced' + max_depth + min_samples_leaf to reduce false positives
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    print("[+] Training model...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Ransomware"]))

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(PE_FEATURE_COLUMNS, FEATURE_COLS_PATH)

    print(f"[+] Model saved to: {MODEL_PATH}")
    print(f"[+] Scaler saved to: {SCALER_PATH}")
    print(f"[+] Feature columns saved to: {FEATURE_COLS_PATH}")

    return acc


def load_model():
    for path in [MODEL_PATH, SCALER_PATH, FEATURE_COLS_PATH]:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Required file not found: {path}\nRun train_model() first."
            )
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_cols = joblib.load(FEATURE_COLS_PATH)
    return model, scaler, feature_cols


def predict_ml(feature_dict: dict):
    """
    Predict ransomware from a dict of PE header features.
    Keys must match PE_FEATURE_COLUMNS.

    Returns:
        prediction (int): 1 = ransomware, 0 = benign
        probability (float): confidence score [0.0 - 1.0]
    """
    model, scaler, feature_cols = load_model()

    try:
        fv = np.array([feature_dict[col] for col in feature_cols]).reshape(1, -1)
    except KeyError as e:
        raise ValueError(f"Missing PE feature: {e}. Required: {feature_cols}")

    fv_scaled = scaler.transform(fv)

    # FIX: Raise threshold to 0.60 to reduce false positives
    probability = float(model.predict_proba(fv_scaled)[0][1])
    prediction = 1 if probability >= 0.60 else 0

    return prediction, probability


if __name__ == "__main__":
    train_model()
