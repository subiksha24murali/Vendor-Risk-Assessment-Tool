"""
Anomaly Detection module for the GRC Risk Analysis Engine.
Uses Isolation Forest to detect abnormal behavior patterns.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for behavioral analysis.
    Detects abnormal login attempts, unusual traffic spikes,
    and unknown behavioral patterns.
    """

    # Behavioral features used for anomaly detection
    BEHAVIOR_FEATURES = [
        "failed_logins",
        "request_rate",
        "traffic_spike",
        "behavior_intensity",
    ]

    def __init__(self, model_path: str = None):
        """Initialize the anomaly detector, optionally loading a saved model."""
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.15,  # ~15% expected anomaly rate
            max_features=1.0,
            random_state=42,
            n_jobs=-1,
        )
        self.is_fitted = False

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def fit(self, df: pd.DataFrame):
        """
        Train the Isolation Forest on behavioral features.

        Args:
            df: DataFrame with preprocessed features.
        """
        available = [c for c in self.BEHAVIOR_FEATURES if c in df.columns]
        if not available:
            raise ValueError(
                f"No behavioral features found. Expected: {self.BEHAVIOR_FEATURES}"
            )

        X = df[available].values
        self.model.fit(X)
        self.is_fitted = True
        print(f"[OK] Anomaly detector trained on {len(df)} samples")

    def predict(self, df: pd.DataFrame) -> bool:
        """
        Detect if the input behavior is anomalous.

        Returns:
            True if anomaly detected, False otherwise.
            -1 from Isolation Forest = anomaly → True
             1 from Isolation Forest = normal  → False
        """
        if not self.is_fitted:
            raise RuntimeError("Anomaly detector has not been fitted yet.")

        available = [c for c in self.BEHAVIOR_FEATURES if c in df.columns]
        X = df[available].values
        prediction = self.model.predict(X)

        # -1 = anomaly, 1 = normal
        return bool(prediction[0] == -1)

    def get_anomaly_score(self, df: pd.DataFrame) -> float:
        """
        Get the raw anomaly score from the Isolation Forest.
        Lower (more negative) scores indicate stronger anomalies.

        Returns:
            Anomaly score as float.
        """
        if not self.is_fitted:
            raise RuntimeError("Anomaly detector has not been fitted yet.")

        available = [c for c in self.BEHAVIOR_FEATURES if c in df.columns]
        X = df[available].values
        score = self.model.decision_function(X)
        return float(score[0])

    def save_model(self, path: str):
        """Save the trained Isolation Forest model to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)
        self.is_fitted = True
        print(f"[OK] Anomaly model saved to {path}")

    def load_model(self, path: str):
        """Load a previously trained model from disk."""
        self.model = joblib.load(path)
        self.is_fitted = True
        print(f"[OK] Anomaly model loaded from {path}")
