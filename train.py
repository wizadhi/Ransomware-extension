"""
train.py — Ransomware Shield Model Trainer

Run this FIRST before starting the server:
    python train.py

This trains the model on PE header features from data_file.csv and saves:
  - ransomware_ml_model.pkl
  - scaler.pkl
  - feature_columns.pkl
"""

from ml_engine import train_model

if __name__ == "__main__":
    train_model()
