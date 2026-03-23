"""
Preprocessing module for the GRC Risk Analysis Engine.
Handles feature encoding, normalization, missing value handling,
and derived feature creation.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import os

from utils.helpers import VULNERABILITY_TYPES, encode_vulnerability_type


class Preprocessor:
    """
    Preprocesses input data for the risk analysis models.
    Encodes categoricals, normalizes numericals, handles missing values,
    and creates derived features.
    """

    FEATURE_COLUMNS = [
        "cvss_score",
        "vulnerability_type",
        "exploit_available",
        "cve_age_days",
        "asset_criticality",
        "internet_exposed",
        "data_sensitivity",
        "failed_logins",
        "request_rate",
        "traffic_spike",
        # Derived features
        "cvss_exploit_interaction",
        "exposure_criticality",
        "cve_recency_score",
        "behavior_intensity",
    ]

    def __init__(self, scaler_path: str = None):
        """Initialize the preprocessor, optionally loading a fitted scaler."""
        self.scaler = StandardScaler()
        self.is_fitted = False

        if scaler_path and os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
            self.is_fitted = True

    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fill missing values with sensible defaults."""
        defaults = {
            "cvss_score": 0.0,
            "vulnerability_type": -1,
            "exploit_available": 0,
            "cve_age_days": 365,
            "asset_criticality": 3,
            "internet_exposed": 0,
            "data_sensitivity": 3,
            "failed_logins": 0,
            "request_rate": 0.0,
            "traffic_spike": 0,
        }
        for col, default in defaults.items():
            if col in df.columns:
                df[col] = df[col].fillna(default)
        return df

    def _encode_categorical(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Encode vulnerability_type to integer if it's a string column.
        """
        if "vulnerability_type" in df.columns:
            if df["vulnerability_type"].dtype == object or isinstance(df["vulnerability_type"].iloc[0], str):
                df["vulnerability_type"] = df["vulnerability_type"].apply(
                    encode_vulnerability_type
                )
            df["vulnerability_type"] = df["vulnerability_type"].astype(int)
        return df


    def _create_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Engineer additional features that capture important interactions.
        """
        # CVSS × Exploit interaction: high CVSS + exploit = much more dangerous
        df["cvss_exploit_interaction"] = df["cvss_score"] * df["exploit_available"]

        # Exposure × Criticality: internet-facing critical assets are high risk
        df["exposure_criticality"] = (
            df["internet_exposed"] * df["asset_criticality"] * df["data_sensitivity"]
        )

        # CVE recency: newer CVEs are more dangerous (exponential decay)
        df["cve_recency_score"] = np.exp(-df["cve_age_days"] / 365.0)

        # Behavior intensity: combines login failures, request rate, and spikes
        df["behavior_intensity"] = (
            np.log1p(df["failed_logins"]) * 0.4
            + np.log1p(df["request_rate"]) * 0.3
            + df["traffic_spike"] * 0.3
        )

        return df

    def _normalize(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Normalize numerical features using StandardScaler."""
        numeric_cols = [
            "cvss_score",
            "cve_age_days",
            "failed_logins",
            "request_rate",
            "cvss_exploit_interaction",
            "exposure_criticality",
            "cve_recency_score",
            "behavior_intensity",
        ]
        existing_cols = [c for c in numeric_cols if c in df.columns]

        if fit:
            df[existing_cols] = self.scaler.fit_transform(df[existing_cols])
            self.is_fitted = True
        else:
            df[existing_cols] = self.scaler.transform(df[existing_cols])

        return df

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Full preprocessing pipeline for TRAINING data.
        Fits the scaler and transforms.
        """
        df = df.copy()
        df = self._handle_missing_values(df)
        df = self._encode_categorical(df)
        df = self._create_derived_features(df)
        df = self._normalize(df, fit=True)
        return df[self.FEATURE_COLUMNS]

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Full preprocessing pipeline for INFERENCE data.
        Uses previously fitted scaler.
        """
        df = df.copy()
        df = self._handle_missing_values(df)
        df = self._encode_categorical(df)
        df = self._create_derived_features(df)
        df = self._normalize(df, fit=False)
        return df[self.FEATURE_COLUMNS]

    def transform_single(self, input_data: dict) -> pd.DataFrame:
        """
        Preprocess a single input record (dict) for prediction.
        Returns a DataFrame with one row ready for model inference.
        """
        df = pd.DataFrame([input_data])
        return self.transform(df)

    def save_scaler(self, path: str):
        """Save the fitted scaler to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.scaler, path)
        print(f"[OK] Scaler saved to {path}")

    def load_scaler(self, path: str):
        """Load a previously fitted scaler from disk."""
        self.scaler = joblib.load(path)
        self.is_fitted = True
        print(f"[OK] Scaler loaded from {path}")
