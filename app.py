"""
Flask web server for the GRC Risk Analysis Engine.
Serves the web dashboard and provides REST API for risk analysis.
"""

import os
import sys
import json
import traceback
from flask import Flask, render_template, request, jsonify

from predict import RiskPredictor
from utils.helpers import timestamp

app = Flask(__name__)

# Initialize predictor globally
predictor = None


def get_predictor():
    """Lazily initialize the predictor."""
    global predictor
    if predictor is None:
        try:
            predictor = RiskPredictor()
        except FileNotFoundError as e:
            print(f"[!] {e}")
            print("[!] Please run 'python train.py' first.")
            raise
    return predictor


@app.route("/")
def index():
    """Serve the main dashboard."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": timestamp(),
        "models_loaded": predictor is not None,
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Analyze risk from input data.

    Expects JSON body with:
        cvss_score, vulnerability_type, exploit_available, cve_age_days,
        asset_criticality, internet_exposed, data_sensitivity,
        failed_logins, request_rate, traffic_spike
    """
    try:
        data = request.get_json(force=True)

        # Validate required fields
        required = [
            "cvss_score", "vulnerability_type", "exploit_available",
            "cve_age_days", "asset_criticality", "internet_exposed",
            "data_sensitivity", "failed_logins", "request_rate", "traffic_spike",
        ]
        missing = [f for f in required if f not in data]
        if missing:
            return jsonify({
                "error": f"Missing fields: {', '.join(missing)}",
                "required_fields": required,
            }), 400

        # Convert types
        input_data = {
            "cvss_score": float(data["cvss_score"]),
            "vulnerability_type": data["vulnerability_type"],
            "exploit_available": int(data["exploit_available"]),
            "cve_age_days": int(data["cve_age_days"]),
            "asset_criticality": int(data["asset_criticality"]),
            "internet_exposed": int(data["internet_exposed"]),
            "data_sensitivity": int(data["data_sensitivity"]),
            "failed_logins": int(data["failed_logins"]),
            "request_rate": float(data["request_rate"]),
            "traffic_spike": int(data["traffic_spike"]),
        }

        pred = get_predictor()
        result = pred.predict(input_data)
        result["timestamp"] = timestamp()
        result["input"] = input_data

        return jsonify(result)

    except FileNotFoundError:
        return jsonify({
            "error": "Models not trained. Please run 'python train.py' first."
        }), 503

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "error": str(e),
            "type": type(e).__name__,
        }), 500


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  GRC RISK ANALYSIS ENGINE — WEB DASHBOARD")
    print("=" * 60)
    print("  Starting server at http://localhost:5000")
    print("  Press Ctrl+C to stop\n")

    app.run(host="0.0.0.0", port=5000, debug=True)
