"""
Prediction module for the GRC Risk Analysis Engine.
Loads trained models and runs end-to-end risk analysis on input data.
"""

import os
import numpy as np
import pandas as pd
import xgboost as xgb
import joblib

from preprocessing import Preprocessor
from anomaly import AnomalyDetector
from utils.helpers import (
    get_risk_level,
    compute_risk_score,
    get_recommendations,
    generate_vulnerability_summary,
    decode_vulnerability_type,
    format_output,
)


class RiskPredictor:
    """
    End-to-end risk analysis predictor.
    Orchestrates preprocessing → XGBoost prediction → anomaly detection →
    risk adjustment → summary generation → recommendations.
    """

    def __init__(self, model_dir: str = None):
        """
        Initialize the predictor by loading all trained models.

        Args:
            model_dir: Path to directory containing trained models.
                       Defaults to './model/' relative to project root.
        """
        if model_dir is None:
            base = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(base, "model")

        self.model_dir = model_dir

        # Load XGBoost risk model
        risk_model_path = os.path.join(model_dir, "risk_model.pkl")
        if not os.path.exists(risk_model_path):
            raise FileNotFoundError(
                f"Risk model not found at {risk_model_path}. Run train.py first."
            )
        self.risk_model = joblib.load(risk_model_path)
        print(f"[OK] Risk model loaded from {risk_model_path}")

        # Load anomaly detector
        anomaly_model_path = os.path.join(model_dir, "anomaly_model.pkl")
        if not os.path.exists(anomaly_model_path):
            raise FileNotFoundError(
                f"Anomaly model not found at {anomaly_model_path}. Run train.py first."
            )
        self.anomaly_detector = AnomalyDetector(model_path=anomaly_model_path)

        # Load preprocessor with fitted scaler
        scaler_path = os.path.join(model_dir, "scaler.pkl")
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(
                f"Scaler not found at {scaler_path}. Run train.py first."
            )
        self.preprocessor = Preprocessor(scaler_path=scaler_path)

    def predict(self, input_data: dict) -> dict:
        """
        Run full risk analysis on a single input.

        Args:
            input_data: Dictionary with keys:
                - cvss_score (float)
                - vulnerability_type (str or int)
                - exploit_available (int/bool)
                - cve_age_days (int)
                - asset_criticality (int)
                - internet_exposed (int/bool)
                - data_sensitivity (int)
                - failed_logins (int)
                - request_rate (float)
                - traffic_spike (int/bool)

        Returns:
            Dictionary with:
                - risk_score (int, 0-100)
                - risk_level (str: Low/Medium/High)
                - anomaly_detected (bool)
                - vulnerability_summary (str)
                - recommended_actions (list[str])
        """
        # ─── Step 1: Preprocess input ────────────────────────────────
        X = self.preprocessor.transform_single(input_data)

        # ─── Step 2: Predict risk level via XGBoost ──────────────────
        risk_label = int(self.risk_model.predict(X)[0])
        probabilities = self.risk_model.predict_proba(X)[0]

        # ─── Step 3: Calculate risk score ────────────────────────────
        risk_score = compute_risk_score(risk_label, probabilities)

        # ─── Step 4: Detect anomalies ────────────────────────────────
        anomaly_detected = self.anomaly_detector.predict(X)
        anomaly_score = self.anomaly_detector.get_anomaly_score(X)

        # ─── Step 5: Apply risk adjustments ──────────────────────────
        risk_score, risk_label = self._adjust_risk(
            risk_score, risk_label, anomaly_detected, input_data
        )

        risk_level = get_risk_level(risk_label)

        # ─── Step 6: Generate summary ────────────────────────────────
        vuln_type = input_data.get("vulnerability_type", "Unknown")
        if isinstance(vuln_type, (int, np.integer)):
            vuln_type = decode_vulnerability_type(int(vuln_type))

        summary = generate_vulnerability_summary(
            vuln_type=vuln_type,
            cvss_score=input_data.get("cvss_score", 0.0),
            exploit_available=bool(input_data.get("exploit_available", 0)),
            internet_exposed=bool(input_data.get("internet_exposed", 0)),
            asset_criticality=input_data.get("asset_criticality", 3),
            anomaly_detected=anomaly_detected,
        )

        # ─── Step 7: Get recommendations ─────────────────────────────
        actions = get_recommendations(risk_level)

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "anomaly_detected": anomaly_detected,
            "anomaly_score": round(anomaly_score, 4),
            "confidence": {
                "low": round(float(probabilities[0]) * 100, 1),
                "medium": round(float(probabilities[1]) * 100, 1),
                "high": round(float(probabilities[2]) * 100, 1),
            },
            "vulnerability_summary": summary,
            "recommended_actions": actions,
        }

    def _adjust_risk(
        self,
        risk_score: int,
        risk_label: int,
        anomaly_detected: bool,
        input_data: dict,
    ) -> tuple:
        """
        Apply post-prediction risk adjustments based on business rules.

        Rules:
            1. If anomaly detected → increase risk score by 10-15
            2. If asset criticality >= 4 → amplify score by 10%
            3. If no exploit available → reduce score by 5
        """
        adjustment = 0

        # Rule 1: Anomaly amplification
        if anomaly_detected:
            adjustment += 12

        # Rule 2: High-criticality asset amplification
        criticality = input_data.get("asset_criticality", 3)
        if criticality >= 4:
            adjustment += int(risk_score * 0.10)

        # Rule 3: No exploit → slight reduction
        if not bool(input_data.get("exploit_available", 0)):
            adjustment -= 5

        # Apply adjustment
        risk_score = int(np.clip(risk_score + adjustment, 0, 100))

        # Re-classify after adjustment
        if risk_score < 40:
            risk_label = 0
        elif risk_score < 70:
            risk_label = 1
        else:
            risk_label = 2

        return risk_score, risk_label

    def predict_batch(self, records: list) -> list:
        """
        Run risk analysis on multiple records.

        Args:
            records: List of input dictionaries.

        Returns:
            List of result dictionaries.
        """
        results = []
        for record in records:
            result = self.predict(record)
            results.append(result)
        return results
