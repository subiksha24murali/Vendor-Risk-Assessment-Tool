"""
Synthetic dataset generator for the GRC Risk Analysis Engine.
Generates realistic cybersecurity data for training the XGBoost
and Isolation Forest models.
"""

import numpy as np
import pandas as pd
import os

from utils.helpers import VULNERABILITY_TYPES, ensure_directories


def generate_dataset(n_samples: int = 2000, seed: int = 42) -> pd.DataFrame:
    """
    Generate a synthetic GRC risk dataset with realistic distributions.

    Columns:
        cvss_score         : float [0-10]
        vulnerability_type : int (encoded)
        exploit_available  : 0 or 1
        cve_age_days       : int [0-3650]
        asset_criticality  : int [1-5]
        internet_exposed   : 0 or 1
        data_sensitivity   : int [1-5]
        failed_logins      : int [0-500]
        request_rate       : float [0-10000]
        traffic_spike      : 0 or 1
        risk_label         : 0 (Low), 1 (Medium), 2 (High)

    Returns:
        pd.DataFrame with n_samples rows.
    """
    rng = np.random.RandomState(seed)

    # ─── Vulnerability Data ──────────────────────────────────────────
    # CVSS: beta distribution skewed toward mid-range, scaled to 0-10
    cvss_score = np.round(rng.beta(2, 3, n_samples) * 10, 1)

    # Vulnerability type: uniform across types
    vuln_types = list(VULNERABILITY_TYPES.values())
    vulnerability_type = rng.choice(vuln_types, n_samples)

    # Exploit availability: ~30% have public exploits
    exploit_available = rng.binomial(1, 0.3, n_samples)

    # CVE age: mixture of recent and old CVEs
    cve_age_days = np.where(
        rng.random(n_samples) < 0.4,
        rng.randint(0, 90, n_samples),       # 40% are recent (< 90 days)
        rng.randint(90, 3650, n_samples),     # 60% are older
    )

    # ─── Asset Data ──────────────────────────────────────────────────
    asset_criticality = rng.choice([1, 2, 3, 4, 5], n_samples, p=[0.1, 0.2, 0.3, 0.25, 0.15])
    internet_exposed = rng.binomial(1, 0.35, n_samples)
    data_sensitivity = rng.choice([1, 2, 3, 4, 5], n_samples, p=[0.1, 0.15, 0.3, 0.25, 0.2])

    # ─── Behavior Data ───────────────────────────────────────────────
    # Failed logins: mostly low, with some spikes
    failed_logins = np.where(
        rng.random(n_samples) < 0.85,
        rng.poisson(3, n_samples),            # Normal: ~3 avg
        rng.poisson(50, n_samples),           # Anomalous: ~50 avg
    )

    # Request rate: log-normal distribution
    request_rate = np.round(rng.lognormal(4, 1.5, n_samples), 2)
    request_rate = np.clip(request_rate, 0, 10000)

    # Traffic spikes: ~20% have spikes
    traffic_spike = rng.binomial(1, 0.2, n_samples)

    # ─── Risk Label Calculation (rule-based ground truth) ────────────
    # Composite score from weighted factors
    risk_raw = (
        (cvss_score / 10.0) * 30                    # CVSS weight: 30%
        + exploit_available * 20                      # Exploit: 20%
        + (asset_criticality / 5.0) * 15              # Criticality: 15%
        + internet_exposed * 10                       # Exposure: 10%
        + (data_sensitivity / 5.0) * 10               # Sensitivity: 10%
        + np.clip(failed_logins / 100.0, 0, 1) * 5   # Login anomalies: 5%
        + traffic_spike * 5                           # Traffic spikes: 5%
        + np.exp(-cve_age_days / 365.0) * 5           # CVE recency: 5%
    )

    # Add some realistic noise
    risk_raw += rng.normal(0, 3, n_samples)
    risk_raw = np.clip(risk_raw, 0, 100)

    # Classify into risk labels
    risk_label = np.where(risk_raw < 35, 0, np.where(risk_raw < 60, 1, 2))

    # ─── Build DataFrame ─────────────────────────────────────────────
    df = pd.DataFrame({
        "cvss_score": cvss_score,
        "vulnerability_type": vulnerability_type,
        "exploit_available": exploit_available,
        "cve_age_days": cve_age_days,
        "asset_criticality": asset_criticality,
        "internet_exposed": internet_exposed,
        "data_sensitivity": data_sensitivity,
        "failed_logins": failed_logins,
        "request_rate": request_rate,
        "traffic_spike": traffic_spike,
        "risk_label": risk_label.astype(int),
    })

    return df


def save_dataset(df: pd.DataFrame, path: str):
    """Save the dataset to CSV."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    print(f"[OK] Dataset saved to {path} ({len(df)} samples)")


if __name__ == "__main__":
    base = ensure_directories()
    dataset_path = os.path.join(base, "dataset", "risk_dataset.csv")

    print("[*] Generating synthetic GRC risk dataset...")
    df = generate_dataset(n_samples=2000)

    # Print class distribution
    print(f"\n    Class Distribution:")
    for label, name in {0: "Low", 1: "Medium", 2: "High"}.items():
        count = (df["risk_label"] == label).sum()
        pct = count / len(df) * 100
        print(f"      {name}: {count} ({pct:.1f}%)")

    save_dataset(df, dataset_path)
    print(f"\n    Columns: {list(df.columns)}")
    print(f"    Shape:   {df.shape}")
