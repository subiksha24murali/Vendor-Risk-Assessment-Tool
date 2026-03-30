"""
Training module for the GRC Risk Analysis Engine.
Trains XGBoost Classifier for risk prediction and
Isolation Forest for anomaly detection.
"""

import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import xgboost as xgb
import joblib
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt

from data_generator import generate_dataset, save_dataset
from preprocessing import Preprocessor
from anomaly import AnomalyDetector
from utils.helpers import ensure_directories, RISK_LEVELS


def train_risk_model(X_train, y_train, X_test, y_test) -> xgb.XGBClassifier:
    """
    Train XGBoost Classifier for risk level prediction.

    Returns:
        Trained XGBClassifier model.
    """
    print("\n" + "=" * 60)
    print("  TRAINING XGBOOST RISK CLASSIFIER")
    print("=" * 60)

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        objective="multi:softprob",
        num_class=3,
        eval_metric="mlogloss",
        random_state=42,
        use_label_encoder=False,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n  Test Accuracy: {accuracy:.4f} ({accuracy * 100:.1f}%)")
    print(f"\n  Classification Report:")

    target_names = [RISK_LEVELS[i] for i in sorted(RISK_LEVELS.keys())]
    report = classification_report(y_test, y_pred, target_names=target_names)
    print(report)

    return model


def train_anomaly_model(X_train) -> AnomalyDetector:
    """
    Train Isolation Forest for anomaly detection.

    Returns:
        Trained AnomalyDetector instance.
    """
    print("\n" + "=" * 60)
    print("  TRAINING ISOLATION FOREST ANOMALY DETECTOR")
    print("=" * 60)

    detector = AnomalyDetector()
    detector.fit(X_train)

    return detector


def plot_feature_importance(model: xgb.XGBClassifier, feature_names: list, save_path: str):
    """Save a bar chart of XGBoost feature importances."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(feature_names)))

    ax.barh(
        range(len(feature_names)),
        importances[indices],
        color=colors,
        edgecolor="white",
        linewidth=0.5,
    )
    ax.set_yticks(range(len(feature_names)))
    ax.set_yticklabels([feature_names[i] for i in indices])
    ax.set_xlabel("Feature Importance")
    ax.set_title("XGBoost Risk Model — Feature Importance")
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Feature importance plot saved to {save_path}")


def plot_confusion_matrix(y_true, y_pred, save_path: str):
    """Save a confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    labels = ["Low", "Medium", "High"]

    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.set_title("Risk Classification — Confusion Matrix")
    plt.colorbar(im, ax=ax)

    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")

    # Add text annotations
    for i in range(len(labels)):
        for j in range(len(labels)):
            color = "white" if cm[i, j] > cm.max() / 2 else "black"
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color, fontsize=14)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[OK] Confusion matrix saved to {save_path}")


def main():
    """Main training pipeline."""
    base = ensure_directories()
    model_dir = os.path.join(base, "model")
    dataset_dir = os.path.join(base, "dataset")
    os.makedirs(model_dir, exist_ok=True)
    os.makedirs(dataset_dir, exist_ok=True)

    # ─── Step 1: Generate or load dataset ────────────────────────────
    dataset_path = os.path.join(dataset_dir, "risk_dataset.csv")

    if os.path.exists(dataset_path):
        print(f"[*] Loading existing dataset from {dataset_path}")
        df = pd.read_csv(dataset_path)
    else:
        print("[*] Generating synthetic dataset...")
        df = generate_dataset(n_samples=2000)
        save_dataset(df, dataset_path)

    print(f"[OK] Dataset: {df.shape[0]} samples, {df.shape[1]} features")

    # ─── Step 2: Preprocess ──────────────────────────────────────────
    print("\n[*] Preprocessing data...")
    preprocessor = Preprocessor()

    y = df["risk_label"].values
    X = preprocessor.fit_transform(df.drop(columns=["risk_label"]))

    print(f"[OK] Features after engineering: {list(X.columns)}")
    print(f"[OK] Feature matrix shape: {X.shape}")

    # Save the fitted scaler
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    preprocessor.save_scaler(scaler_path)

    # ─── Step 3: Split data ──────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[*] Train/Test split: {len(X_train)}/{len(X_test)}")

    # ─── Step 4: Train XGBoost risk model ────────────────────────────
    risk_model = train_risk_model(X_train, y_train, X_test, y_test)

    # Save model
    risk_model_path = os.path.join(model_dir, "risk_model.pkl")
    joblib.dump(risk_model, risk_model_path)
    print(f"[OK] Risk model saved to {risk_model_path}")

    # ─── Step 5: Train Isolation Forest anomaly detector ─────────────
    anomaly_detector = train_anomaly_model(X_train)

    anomaly_model_path = os.path.join(model_dir, "anomaly_model.pkl")
    anomaly_detector.save_model(anomaly_model_path)

    # ─── Step 6: Generate evaluation plots ───────────────────────────
    print("\n[*] Generating evaluation plots...")

    plot_feature_importance(
        risk_model,
        list(X.columns),
        os.path.join(model_dir, "feature_importance.png"),
    )

    y_pred = risk_model.predict(X_test)
    plot_confusion_matrix(
        y_test, y_pred,
        os.path.join(model_dir, "confusion_matrix.png"),
    )

    # ─── Summary ─────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Models saved to:     {model_dir}/")
    print(f"  Dataset saved to:    {dataset_path}")
    print(f"  XGBoost accuracy:    {accuracy_score(y_test, y_pred):.1%}")
    print(f"  Anomaly model:       Isolation Forest (200 estimators)")
    print("=" * 60)
##subi

if __name__ == "__main__":
    main()
