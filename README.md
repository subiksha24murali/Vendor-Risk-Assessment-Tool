# Vendor Risk Assessment Tool (AI GRC Engine)

An advanced Cybersecurity Risk Analysis System designed for Governance, Risk, and Compliance (GRC). This tool uses Machine Learning (XGBoost & Isolation Forest) to analyze security data, calculate dynamic risk scores, classify risk levels, detect behavioral anomalies, and provide actionable remediation steps — entirely locally, without relying on external APIs or LLMs.

## Features

- **XGBoost Risk Scoring**: Calculates a dynamic risk score (0-100) and categorizes it into Low, Medium, and High based on vulnerability characteristics and asset context.
- **Isolation Forest Anomaly Detection**: Flags unusual behavior patterns (e.g., traffic spikes, abnormal failed login attempts).
- **Synthetic Data Generation**: Includes a script to generate realistic training datasets tailored for GRC risk profiles.
- **Premium Web Dashboard**: A modern, responsive Flask-based web interface featuring real-time risk gauges, anomaly indicators, and vulnerability summaries.
- **Interactive Console Mode**: Run the analysis engine directly from the command line, either interactively or using full demo scenarios.

## Project Structure

```text
├── app.py                  # Flask web server and API endpoints
├── main.py                 # CLI entry point (Demo & Interactive mode)
├── train.py                # ML model training pipeline
├── predict.py              # Risk scoring and inference module
├── preprocessing.py        # Feature engineering and scaling
├── anomaly.py              # Isolation Forest anomaly detection
├── data_generator.py       # Synthetic dataset generator
├── requirements.txt        # Python dependencies
├── utils/
│   └── helpers.py          # Encoders, logic mapping, formatting
├── static/
│   ├── css/style.css       # Dashboard styles
│   └── js/app.js           # Dashboard frontend logic
├── templates/
│   └── index.html          # Dashboard HTML template
├── dataset/                # Generated training data (csv)
└── model/                  # Saved ML models and scalers
```

## Setup Instructions

### Prerequisites
- Python 3.8+

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/subiksha24murali/Vendor-Risk-Assessment-Tool.git
   cd Vendor-Risk-Assessment-Tool
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Training the Models
Before running the application, you **must** generate the synthetic dataset and train the ML models:
```bash
python train.py
```
This script will:
1. Generate `dataset/risk_dataset.csv` (2000 samples).
2. Train the XGBoost risk model and the Isolation Forest anomaly model.
3. Save the trained models to the `model/` directory, along with evaluation plots.

---

## Usage Modalities

### 1. Web Dashboard
Start the Flask application to access the premium web dashboard:
```bash
python app.py
```
Then open your browser and navigate to `http://localhost:5000`.

### 2. Command Line (Demo Mode)
Run a suite of predefined cybersecurity scenarios to see how the engine evaluates different risk profiles:
```bash
python main.py
```

### 3. Command Line (Interactive Mode)
Input custom vulnerability, asset, and behavior data via the terminal to get real-time risk assessments:
```bash
python main.py --interactive
```

## Technology Stack
- **Backend / API**: Python, Flask
- **Machine Learning**: scikit-learn, XGBoost, pandas, numpy
- **Frontend**: HTML5, Vanilla CSS (Glassmorphism design), JavaScript

## License
MIT License
