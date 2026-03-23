"""
Utility helpers for the GRC Risk Analysis Engine.
Provides vulnerability type encoding, risk mapping, recommendations,
and summary generation — all rule-based, no external APIs.
"""

import numpy as np
import pandas as pd
import os
import json
from datetime import datetime


# ─── Vulnerability Type Encoding ────────────────────────────────────────────

VULNERABILITY_TYPES = {
    "SQLi": 0,
    "XSS": 1,
    "SSRF": 2,
    "RCE": 3,
    "LFI": 4,
    "RFI": 5,
    "CSRF": 6,
    "IDOR": 7,
    "XXE": 8,
    "Open Redirect": 9,
    "Buffer Overflow": 10,
    "Privilege Escalation": 11,
    "Auth Bypass": 12,
    "Info Disclosure": 13,
    "DoS": 14,
}

VULNERABILITY_TYPES_REVERSE = {v: k for k, v in VULNERABILITY_TYPES.items()}

# Severity weight per vulnerability type (higher = more dangerous)
VULN_SEVERITY_WEIGHT = {
    "SQLi": 0.9,
    "XSS": 0.5,
    "SSRF": 0.7,
    "RCE": 1.0,
    "LFI": 0.6,
    "RFI": 0.7,
    "CSRF": 0.4,
    "IDOR": 0.5,
    "XXE": 0.7,
    "Open Redirect": 0.3,
    "Buffer Overflow": 0.95,
    "Privilege Escalation": 0.85,
    "Auth Bypass": 0.8,
    "Info Disclosure": 0.3,
    "DoS": 0.6,
}


# ─── Risk Classification ────────────────────────────────────────────────────

RISK_LEVELS = {
    0: "Low",
    1: "Medium",
    2: "High",
}

RISK_SCORE_RANGES = {
    "Low": (0, 39),
    "Medium": (40, 69),
    "High": (70, 100),
}


# ─── Recommended Actions ────────────────────────────────────────────────────

RECOMMENDED_ACTIONS = {
    "Low": [
        "Monitor system logs regularly",
        "Maintain current security controls",
        "Schedule routine vulnerability scans",
        "Review access permissions periodically",
    ],
    "Medium": [
        "Apply security patches within 7 days",
        "Increase monitoring frequency",
        "Restrict unnecessary network access",
        "Review and update firewall rules",
        "Conduct targeted vulnerability assessment",
    ],
    "High": [
        "Apply critical patches immediately",
        "Block known exploit vectors",
        "Enable strict firewall and WAF rules",
        "Conduct full security audit",
        "Isolate affected assets from network",
        "Activate incident response procedures",
        "Enable enhanced logging and monitoring",
    ],
}


def encode_vulnerability_type(vuln_type: str) -> int:
    """Encode a vulnerability type string to integer."""
    return VULNERABILITY_TYPES.get(vuln_type, -1)


def decode_vulnerability_type(encoded: int) -> str:
    """Decode an integer-encoded vulnerability type back to string."""
    return VULNERABILITY_TYPES_REVERSE.get(encoded, "Unknown")


def get_risk_level(label: int) -> str:
    """Convert numeric risk label (0/1/2) to string level."""
    return RISK_LEVELS.get(label, "Unknown")


def compute_risk_score(risk_label: int, probabilities: np.ndarray) -> int:
    """
    Compute a fine-grained risk score (0-100) from the model's
    class probabilities, mapped into the appropriate risk range.

    - Label 0 (Low):    score in [0, 39]
    - Label 1 (Medium): score in [40, 69]
    - Label 2 (High):   score in [70, 100]
    """
    level = get_risk_level(risk_label)
    lo, hi = RISK_SCORE_RANGES[level]

    # Use the confidence for the predicted class to interpolate within range
    confidence = float(probabilities[risk_label])
    score = lo + confidence * (hi - lo)
    return int(np.clip(round(score), 0, 100))


def get_recommendations(risk_level: str) -> list:
    """Return recommended actions for a given risk level."""
    return RECOMMENDED_ACTIONS.get(risk_level, [])


def generate_vulnerability_summary(
    vuln_type: str,
    cvss_score: float,
    exploit_available: bool,
    internet_exposed: bool,
    asset_criticality: int,
    anomaly_detected: bool,
) -> str:
    """
    Generate a human-readable vulnerability summary based on structured data.
    Pure rule-based — no LLM involved.
    """
    parts = []

    # Vulnerability description
    severity = VULN_SEVERITY_WEIGHT.get(vuln_type, 0.5)
    if severity >= 0.8:
        parts.append(f"Critical {vuln_type} vulnerability detected")
    elif severity >= 0.5:
        parts.append(f"{vuln_type} vulnerability identified")
    else:
        parts.append(f"Low-severity {vuln_type} issue found")

    # CVSS context
    if cvss_score >= 9.0:
        parts.append(f"with critical CVSS score of {cvss_score}")
    elif cvss_score >= 7.0:
        parts.append(f"with high CVSS score of {cvss_score}")
    elif cvss_score >= 4.0:
        parts.append(f"with moderate CVSS score of {cvss_score}")
    else:
        parts.append(f"with low CVSS score of {cvss_score}")

    # Exploit status
    if exploit_available:
        parts.append("— public exploit is available")

    # Exposure
    if internet_exposed:
        parts.append("on an internet-facing asset")
    else:
        parts.append("on an internal asset")

    # Asset criticality
    if asset_criticality >= 4:
        parts.append("with high business criticality")
    elif asset_criticality >= 3:
        parts.append("with moderate business criticality")

    # Anomaly
    if anomaly_detected:
        parts.append("| Anomalous behavior detected")

    return " ".join(parts) + "."


def ensure_directories():
    """Create required project directories if they don't exist."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for d in ["model", "dataset"]:
        path = os.path.join(base, d)
        os.makedirs(path, exist_ok=True)
    return base


def format_output(result: dict) -> str:
    """Pretty-format the analysis result for console output."""
    border = "═" * 60
    lines = [
        f"\n╔{border}╗",
        f"║{'AI GRC RISK ANALYSIS REPORT':^60}║",
        f"╠{border}╣",
        f"║  Risk Score:        {str(result['risk_score']).ljust(39)}║",
        f"║  Risk Level:        {result['risk_level'].ljust(39)}║",
        f"║  Anomaly Detected:  {str(result['anomaly_detected']).ljust(39)}║",
        f"╠{border}╣",
        f"║{'VULNERABILITY SUMMARY':^60}║",
        f"╠{border}╣",
    ]

    # Word-wrap summary to fit in box
    summary = result.get("vulnerability_summary", "")
    while len(summary) > 56:
        split_at = summary[:56].rfind(" ")
        if split_at == -1:
            split_at = 56
        lines.append(f"║  {summary[:split_at].ljust(57)}║")
        summary = summary[split_at:].lstrip()
    if summary:
        lines.append(f"║  {summary.ljust(57)}║")

    lines.append(f"╠{border}╣")
    lines.append(f"║{'RECOMMENDED ACTIONS':^60}║")
    lines.append(f"╠{border}╣")

    for i, action in enumerate(result.get("recommended_actions", []), 1):
        action_text = f"  {i}. {action}"
        lines.append(f"║{action_text.ljust(60)}║")

    lines.append(f"╚{border}╝\n")
    return "\n".join(lines)


def timestamp() -> str:
    """Return current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
