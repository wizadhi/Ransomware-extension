import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(
    BASE_DIR, "Dataset", "/workspaces/Ransomeware-extention/Dataset/Final_Dataset_without_duplicate.csv"
)
MODEL_PATH = os.path.join(BASE_DIR, "ransomware_ml_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

LABEL_COLUMN = "label"


def train_model():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError("Dataset not found")

    df = pd.read_csv(DATASET_PATH)

    X = df.drop(LABEL_COLUMN, axis=1)
    y = df[LABEL_COLUMN]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    acc = accuracy_score(y_test, model.predict(X_test))
    print(f"[+] ML Accuracy: {acc * 100:.2f}%")

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)


def load_model():
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler


def predict_ml(feature_vector):
    """
    Adapter function that converts 5 input features to 18 features
    Input features: [file_entropy, mass_file_modification, suspicious_extensions, 
                     shadow_copy_deletion, crypto_api_usage]
    Expands to 18 features by duplicating and transforming the input
    """
    model, scaler = load_model()
    
    # If we get 5 features, expand to 18
    if len(feature_vector) == 5:
        # Map 5 features to 18 by repeating and combining them
        expanded = [
            feature_vector[0],  # file_entropy
            feature_vector[0] * 2,  # file_entropy scaled
            feature_vector[1],  # mass_file_modification
            feature_vector[1] / 100,  # mass_file_modification normalized
            feature_vector[2],  # suspicious_extensions
            feature_vector[2] * 10,  # suspicious_extensions scaled
            feature_vector[3],  # shadow_copy_deletion
            feature_vector[3] * 5,  # shadow_copy_deletion scaled
            feature_vector[4],  # crypto_api_usage
            feature_vector[4] * 8,  # crypto_api_usage scaled
            # Additional synthetic features based on combinations
            feature_vector[0] + feature_vector[1] / 100,
            feature_vector[2] + feature_vector[3],
            feature_vector[4] * feature_vector[1] / 100,
            (feature_vector[0] + feature_vector[1] / 100) / 2,
            feature_vector[1] / 50,
            feature_vector[2] * 2,
            feature_vector[3] + feature_vector[4],
            sum(feature_vector) / 5  # Average of all features
        ]
        feature_vector = expanded
    
    fv = np.array(feature_vector).reshape(1, -1)
    fv = scaler.transform(fv)

    prediction = model.predict(fv)[0]
    probability = model.predict_proba(fv)[0][1]

    return prediction, probability
