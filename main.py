"""
Main entry point for the GRC Risk Analysis Engine.
Demonstrates the full pipeline: load → preprocess → predict → report.
"""

import os
import sys
import json

from predict import RiskPredictor
from utils.helpers import format_output, decode_vulnerability_type, timestamp


def run_demo():
    """Run demonstration with sample cybersecurity scenarios."""

    print("\n" + "=" * 60)
    print("  AI-POWERED GRC RISK ANALYSIS ENGINE")
    print(f"  Timestamp: {timestamp()}")
    print("=" * 60)

    # Initialize predictor (loads all trained models)
    try:
        predictor = RiskPredictor()
    except FileNotFoundError as e:
        print(f"\n[!] Error: {e}")
        print("[!] Please run 'python train.py' first to train the models.")
        sys.exit(1)

    # ─── Sample Scenarios ────────────────────────────────────────────

    scenarios = [
        {
            "name": "Critical SQL Injection on Production Server",
            "data": {
                "cvss_score": 9.8,
                "vulnerability_type": "SQLi",
                "exploit_available": 1,
                "cve_age_days": 15,
                "asset_criticality": 5,
                "internet_exposed": 1,
                "data_sensitivity": 5,
                "failed_logins": 150,
                "request_rate": 5000.0,
                "traffic_spike": 1,
            },
        },
        {
            "name": "Medium-Risk XSS on Internal App",
            "data": {
                "cvss_score": 5.4,
                "vulnerability_type": "XSS",
                "exploit_available": 0,
                "cve_age_days": 180,
                "asset_criticality": 3,
                "internet_exposed": 0,
                "data_sensitivity": 3,
                "failed_logins": 5,
                "request_rate": 200.0,
                "traffic_spike": 0,
            },
        },
        {
            "name": "Low-Risk Info Disclosure on Dev Environment",
            "data": {
                "cvss_score": 2.1,
                "vulnerability_type": "Info Disclosure",
                "exploit_available": 0,
                "cve_age_days": 730,
                "asset_criticality": 1,
                "internet_exposed": 0,
                "data_sensitivity": 1,
                "failed_logins": 0,
                "request_rate": 50.0,
                "traffic_spike": 0,
            },
        },
        {
            "name": "RCE with Active Exploitation Attempt",
            "data": {
                "cvss_score": 10.0,
                "vulnerability_type": "RCE",
                "exploit_available": 1,
                "cve_age_days": 3,
                "asset_criticality": 5,
                "internet_exposed": 1,
                "data_sensitivity": 5,
                "failed_logins": 500,
                "request_rate": 9500.0,
                "traffic_spike": 1,
            },
        },
        {
            "name": "SSRF on Staging with Anomalous Traffic",
            "data": {
                "cvss_score": 7.5,
                "vulnerability_type": "SSRF",
                "exploit_available": 1,
                "cve_age_days": 45,
                "asset_criticality": 3,
                "internet_exposed": 1,
                "data_sensitivity": 4,
                "failed_logins": 80,
                "request_rate": 3000.0,
                "traffic_spike": 1,
            },
        },
    ]

    # ─── Run Analysis ────────────────────────────────────────────────

    results = []
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{'─' * 60}")
        print(f"  SCENARIO {i}: {scenario['name']}")
        print(f"{'─' * 60}")

        result = predictor.predict(scenario["data"])
        results.append(result)

        print(format_output(result))

    # ─── Summary Table ───────────────────────────────────────────────

    print("\n" + "=" * 60)
    print("  ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"  {'Scenario':<45} {'Score':>5} {'Level':<8} {'Anomaly':<8}")
    print(f"  {'─' * 45} {'─' * 5} {'─' * 8} {'─' * 8}")

    for scenario, result in zip(scenarios, results):
        name = scenario["name"][:44]
        print(
            f"  {name:<45} {result['risk_score']:>5} "
            f"{result['risk_level']:<8} {'Yes' if result['anomaly_detected'] else 'No':<8}"
        )

    print("\n" + "=" * 60)

    return results


def run_interactive():
    """Interactive mode: accept user input for analysis."""
    print("\n  ═══ INTERACTIVE RISK ANALYSIS ═══\n")

    try:
        predictor = RiskPredictor()
    except FileNotFoundError as e:
        print(f"\n[!] Error: {e}")
        print("[!] Please run 'python train.py' first to train the models.")
        sys.exit(1)

    while True:
        print("\nEnter vulnerability data (or 'quit' to exit):")
        try:
            cvss = input("  CVSS Score (0-10): ").strip()
            if cvss.lower() == "quit":
                break

            input_data = {
                "cvss_score": float(cvss),
                "vulnerability_type": input("  Vulnerability Type (SQLi/XSS/RCE/SSRF/etc): ").strip(),
                "exploit_available": int(input("  Exploit Available (0/1): ").strip()),
                "cve_age_days": int(input("  CVE Age (days): ").strip()),
                "asset_criticality": int(input("  Asset Criticality (1-5): ").strip()),
                "internet_exposed": int(input("  Internet Exposed (0/1): ").strip()),
                "data_sensitivity": int(input("  Data Sensitivity (1-5): ").strip()),
                "failed_logins": int(input("  Failed Logins: ").strip()),
                "request_rate": float(input("  Request Rate: ").strip()),
                "traffic_spike": int(input("  Traffic Spike (0/1): ").strip()),
            }

            result = predictor.predict(input_data)
            print(format_output(result))

        except (ValueError, KeyError) as e:
            print(f"\n[!] Invalid input: {e}. Please try again.")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        run_interactive()
    else:
        run_demo()
