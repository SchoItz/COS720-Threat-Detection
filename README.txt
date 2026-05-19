COS720 – AI-Powered Insider Threat Detection System
====================================================
University of Pretoria | Computer Information & Security I | 2026

QUICK START
-----------
1. Install Python 3.9+ if not already installed.

2. Install dependencies:
       cd prototype
       pip install -r requirements.txt

3. Place the Kaggle dataset in prototype/data/:
   - Download: https://www.kaggle.com/datasets/ahmeduzaki/insider-threat-dataset-for-corporate-environments
   - File name: insider_threat_clean_dataset.csv

4. (Optional) Generate synthetic demo data if dataset not yet available:
       python backend/generate_sample_data.py

5. Train the model:
       python backend/train_model.py
   This will:
   - Train a Random Forest classifier
   - Save model files to prototype/models/
   - Print accuracy, precision, recall, F1-score, confusion matrix
   - Save feature importance and confusion matrix charts to models/

6. Run the web application:
       python backend/app.py
   Then open http://127.0.0.1:5000 in your browser.

NOTE: The app runs in DEMO MODE if train_model.py has not been run yet.
      Demo mode uses a heuristic engine and is suitable for UI demonstration.
      For accurate ML predictions, run train_model.py first.

PROJECT STRUCTURE
-----------------
COS720-Threat-Detection/
├── toWord.txt                   ← All written report content
├── diagrams.txt                 ← Mermaid UML diagrams
└── prototype/
    ├── requirements.txt         ← Python dependencies
    ├── backend/
    │   ├── app.py               ← Flask web application
    │   ├── train_model.py       ← Model training & evaluation
    │   ├── preprocess.py        ← Data preprocessing module
    │   ├── explainability.py    ← AI explainability engine
    │   └── generate_sample_data.py  ← Synthetic data generator
    ├── data/
    │   ├── README.txt
    │   └── insider_threat_clean_dataset.csv  ← Place here (download from Kaggle)
    ├── models/                  ← Created by train_model.py
    │   ├── rf_model.pkl
    │   ├── preprocessor.pkl
    │   ├── thresholds.json
    │   ├── feature_names.json
    │   ├── metrics_report.txt
    │   ├── confusion_matrix.png
    │   └── feature_importance.png
    ├── frontend/
    │   ├── src/
    │   └── build/               ← Pre-built React app (served by Flask)
    ├── templates/
    │   ├── index.html
    │   ├── result.html
    │   └── about.html
    └── static/
        └── style.css
