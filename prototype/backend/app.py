"""
app.py
------
Flask JSON REST API for the AI-Powered Insider Threat Detection System.
COS720 – Computer Information and Security I – Project 2026

Endpoints:
    GET  /api/health          – Health check
    GET  /api/features        – Feature metadata
    GET  /api/samples         – All sample profile metadata
    GET  /api/sample/<id>     – Run prediction on a sample profile
    POST /api/predict         – Predict from JSON body or CSV upload
"""

import os
import sys
import json
import logging
import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# Add prototype dir to path
sys.path.insert(0, os.path.dirname(__file__))

from preprocess import (
    load_preprocessor,
    transform_single_record,
    NUMERIC_FEATURES,
    CATEGORICAL_FEATURES,
    FEATURE_LABELS,
)
from explainability import Explainer
from generate_sample_data import SAMPLE_PROFILES

# ── App Configuration ────────────────────────────────────────────────────────
# Serve the pre-built React frontend from frontend/build/
BUILD_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend", "build")

app = Flask(
    __name__,
    static_folder=os.path.join(BUILD_DIR, "static"),
    static_url_path="/static",
)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB upload limit
CORS(app, resources={r"/api/*": {"origins": "*"}})

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Model Paths ───────────────────────────────────────────────────────────────
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
PREPROCESSOR_PATH = os.path.join(MODELS_DIR, "preprocessor.pkl")
THRESHOLDS_PATH = os.path.join(MODELS_DIR, "thresholds.json")  # legacy, unused
FEATURE_NAMES_PATH = os.path.join(MODELS_DIR, "feature_names.json")  # legacy, unused
MODEL_METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")
MALICIOUS_RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "malicious_results.json")

# ── Load Model at Startup ─────────────────────────────────────────────────────
model = None
preprocessor = None
explainer = None
numeric_features = NUMERIC_FEATURES
categorical_features = CATEGORICAL_FEATURES
model_loaded = False


def load_model():
    """Load the trained model, preprocessor, and explainer."""
    global model, preprocessor, explainer, numeric_features, categorical_features, model_loaded

    try:
        if not os.path.exists(MODEL_PATH):
            logger.warning(
                "Model files not found. Run train_model.py first. "
                "Sample profiles will still work in demo mode."
            )
            model_loaded = False
            return

        model = joblib.load(MODEL_PATH)
        preprocessor = load_preprocessor(PREPROCESSOR_PATH)
        explainer = Explainer(
            metadata_path=MODEL_METADATA_PATH,
        )

        # Load actual feature lists from saved metadata
        if os.path.exists(MODEL_METADATA_PATH):
            with open(MODEL_METADATA_PATH, "r") as f:
                meta = json.load(f)
                numeric_features = meta.get("numeric_features", NUMERIC_FEATURES)
                categorical_features = meta.get("categorical_features", CATEGORICAL_FEATURES)

        model_loaded = True
        logger.info("Model and preprocessor loaded successfully.")

    except Exception as exc:
        logger.error(f"Failed to load model: {exc}")
        model_loaded = False


load_model()


# ── JSON-safe value converter ─────────────────────────────────────────────────
def _safe(v):
    """Convert any value to a JSON-serializable Python native type."""
    if isinstance(v, np.integer):
        return int(v)
    if isinstance(v, np.floating):
        f = float(v)
        return None if (f != f or f == float('inf') or f == float('-inf')) else f
    if isinstance(v, np.bool_):
        return bool(v)
    if isinstance(v, (np.str_, np.bytes_)):
        return str(v)
    if isinstance(v, float):
        return None if (v != v or v == float('inf') or v == float('-inf')) else v
    return v


# ── Helper Functions ──────────────────────────────────────────────────────────
def _predict_record(record: dict) -> dict:
    """
    Run the full prediction pipeline on a single record dict.
    Returns prediction, probability, and explanation.
    """
    if not model_loaded:
        raise RuntimeError(
            "Model is not loaded. Please run train_model.py to train the model first."
        )

    # Transform input
    X = transform_single_record(record, preprocessor, numeric_features, categorical_features)

    # Predict
    prediction = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0]
    probability = float(proba[1])  # Probability of class 1 (Malicious)

    # Explain
    explanation = explainer.explain_prediction(record, prediction, probability)

    return explanation


def _predict_batch_chunked(df: pd.DataFrame, chunk_size: int = 1000) -> list:
    """
    Single-pass vectorized batch prediction.
    Preprocesses and predicts all rows in ONE sklearn call, then filters to
    malicious only. Chunk_size is kept for the result-building loop to avoid
    excessive memory in dict conversion, but ML inference is fully vectorized.
    Only malicious records (prediction == 1) are kept and returned.
    Results are sorted by threat probability (highest first), ranked, and
    saved to MALICIOUS_RESULTS_PATH for later retrieval.
    """
    if not model_loaded:
        raise RuntimeError("Model is not loaded.")

    total_records = len(df)

    # ── 0. Extract ground truth label if the CSV includes is_malicious ─────────
    has_gt = "is_malicious" in df.columns
    gt     = df["is_malicious"].values.astype(int).copy() if has_gt else None

    # ── 1. Prepare columns ────────────────────────────────────────────────────
    for col in numeric_features:
        if col not in df.columns:
            df[col] = 0.0
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
    for col in categorical_features:
        if col not in df.columns:
            df[col] = "unknown"
        else:
            df[col] = df[col].fillna("unknown").astype(str)

    # ── 2. ONE preprocess + predict call for all rows ─────────────────────────
    logger.info("[batch] preprocessing %d rows...", total_records)
    X           = preprocessor.transform(df[numeric_features + categorical_features])
    logger.info("[batch] predicting labels...")
    predictions = model.predict(X)
    logger.info("[batch] computing probabilities...")
    probas      = model.predict_proba(X)[:, 1]
    logger.info("[batch] ML inference complete")

    # ── 3. Boolean mask — probability >= 40% ────────────────────────────────
    mal_mask    = probas >= 0.40
    logger.info("[batch] %d records at >=40%% probability — building results...", int(mal_mask.sum()))
    mal_df          = df[mal_mask].reset_index(drop=True)
    mal_probas      = probas[mal_mask]
    mal_predictions = predictions[mal_mask]
    mal_indices     = np.where(mal_mask)[0]   # original row indices (0-based)

    # ── 4. Vectorized risk counts (only for malicious rows) ───────────────────
    n_mal    = len(mal_df)
    high_cnt = np.zeros(n_mal, dtype=np.int32)
    med_cnt  = np.zeros(n_mal, dtype=np.int32)
    low_cnt  = np.zeros(n_mal, dtype=np.int32)

    for feat in numeric_features:
        baseline = explainer.thresholds.get(feat, {}).get("normal_75th", 0)
        if baseline == 0 or feat not in mal_df.columns:
            continue
        ratios   = mal_df[feat].values / baseline
        high_cnt += (ratios >= 2.0).astype(np.int32)
        med_cnt  += ((ratios >= 1.2) & (ratios < 2.0)).astype(np.int32)
        low_cnt  += ((ratios >= 0.8) & (ratios < 1.2)).astype(np.int32)

    # ── 5. Build result list for flagged rows ────────────────────────────────
    raw_records  = mal_df.to_dict("records")
    all_malicious = []
    for i, raw in enumerate(raw_records):
        rec  = {k: _safe(v) for k, v in raw.items()}
        pred = int(mal_predictions[i])
        row = {
            "prediction":        pred,
            "prediction_label":  "Malicious" if pred == 1 else "Normal",
            "probability":       round(float(mal_probas[i]), 4),
            "confidence_pct":    round(float(mal_probas[i]) * 100, 1),
            "high_risk_count":   int(high_cnt[i]),
            "medium_risk_count": int(med_cnt[i]),
            "low_risk_count":    int(low_cnt[i]),
            "record":            rec,
            "row_index":         int(mal_indices[i]) + 2,
        }
        if has_gt:
            row["actual_label"] = int(gt[mal_indices[i]])
        all_malicious.append(row)

    # ── 6. Sort highest threat first and assign rank ──────────────────────────
    all_malicious.sort(key=lambda x: x["probability"], reverse=True)
    for rank, item in enumerate(all_malicious, start=1):
        item["rank"] = rank

    # ── 6b. Collect false negatives when ground truth is available ─────────────
    false_negatives = []
    if has_gt:
        fn_mask    = (~mal_mask) & (gt == 1)
        fn_indices = np.where(fn_mask)[0]
        fn_df      = df[fn_mask].reset_index(drop=True)
        fn_probas  = probas[fn_mask]
        for i, raw in enumerate(fn_df.to_dict("records")):
            rec = {k: _safe(v) for k, v in raw.items()}
            false_negatives.append({
                "prediction":        0,
                "prediction_label":  "Normal",
                "probability":       round(float(fn_probas[i]), 4),
                "confidence_pct":    round(float(fn_probas[i]) * 100, 1),
                "high_risk_count":   0,
                "medium_risk_count": 0,
                "low_risk_count":    0,
                "record":            rec,
                "row_index":         int(fn_indices[i]) + 2,
                "actual_label":      1,
                "is_false_negative": True,
            })
        logger.info("[batch] GT available — %d FP, %d FN",
                    sum(1 for r in all_malicious if r.get("actual_label") == 0),
                    len(false_negatives))

    fp_count = sum(1 for r in all_malicious if r.get("actual_label") == 0) if has_gt else 0

    # ── 7. Save to disk for later retrieval (non-blocking) ────────────────────
    saved_meta = {
        "total_records":        total_records,
        "flagged_count":        len(all_malicious),
        "saved_at":             pd.Timestamp.now().isoformat(),
        "results":              all_malicious,
        "has_ground_truth":     has_gt,
        "false_positive_count": fp_count,
        "false_negative_count": len(false_negatives),
        "false_negatives":      false_negatives,
    }
    try:
        os.makedirs(os.path.dirname(MALICIOUS_RESULTS_PATH), exist_ok=True)
        with open(MALICIOUS_RESULTS_PATH, "w") as fh:
            json.dump(saved_meta, fh)
        logger.info("[batch] saved %d flagged records to disk", len(all_malicious))
    except Exception as save_err:
        logger.warning("[batch] could not save results to disk: %s", save_err)

    return all_malicious, total_records, false_negatives, has_gt


def _predict_demo(record: dict) -> dict:
    """
    Simple heuristic-based demo prediction for when the model is not trained.
    Used only for demonstration when model files are absent.
    """
    risk_score = 0.0
    risk_score += min(record.get("total_files_burned", 0) / 30, 1.0) * 0.40
    risk_score += min(record.get("burned_from_other", 0) / 15, 1.0) * 0.25
    risk_score += min(record.get("num_printed_pages_off_hours", 0) / 50, 1.0) * 0.15
    risk_score += min(record.get("total_printed_pages", 0) / 150, 1.0) * 0.10
    risk_score += min(record.get("weekend_entry", 0) / 2, 1.0) * 0.05
    risk_score += min(record.get("hostility_country_level", 1) / 4, 1.0) * 0.05
    risk_score += record.get("has_criminal_record", 0) * 0.08

    prediction = 1 if risk_score >= 0.40 else 0
    probability = min(risk_score * 1.1, 0.99) if prediction == 1 else max(1 - risk_score, 0.55)

    # Build a basic explainer result without the trained model
    demo_explainer = Explainer()
    # Provide basic thresholds for demo
    demo_explainer.thresholds = {
        "total_files_burned": {"normal_75th": 15, "normal_mean": 9, "normal_std": 8},
        "burned_from_other": {"normal_75th": 4, "normal_mean": 2, "normal_std": 3},
        "num_printed_pages_off_hours": {"normal_75th": 3, "normal_mean": 0.6, "normal_std": 2},
        "total_printed_pages": {"normal_75th": 20, "normal_mean": 13, "normal_std": 12},
        "num_entries": {"normal_75th": 4, "normal_mean": 3, "normal_std": 1},
        "late_exit_flag": {"normal_75th": 1, "normal_mean": 0.2, "normal_std": 0.4},
        "entry_during_weekend": {"normal_75th": 0.5, "normal_mean": 0.1, "normal_std": 0.3},
        "trip_day_number": {"normal_75th": 2, "normal_mean": 1, "normal_std": 2},
        "hostility_country_level": {"normal_75th": 2, "normal_mean": 1.3, "normal_std": 0.7},
        "has_criminal_record": {"normal_75th": 0, "normal_mean": 0.05, "normal_std": 0.22},
        "employee_seniority_years": {"normal_75th": 18, "normal_mean": 12, "normal_std": 7},
    }
    demo_explainer.numeric_features = numeric_features
    demo_explainer.categorical_features = categorical_features
    demo_explainer.feature_importances = {
        "total_files_burned": 0.35,
        "burned_from_other": 0.22,
        "num_printed_pages_off_hours": 0.15,
        "total_printed_pages": 0.10,
        "num_entries": 0.05,
        "late_exit_flag": 0.04,
        "entry_during_weekend": 0.04,
        "trip_day_number": 0.03,
        "hostility_country_level": 0.03,
        "has_criminal_record": 0.02,
        "employee_seniority_years": 0.01,
    }

    explanation = demo_explainer.explain_prediction(record, prediction, probability)
    explanation["demo_mode"] = True
    return explanation


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model_loaded,
        "mode": "trained" if model_loaded else "demo",
    })


@app.route("/api/features")
def features():
    return jsonify({
        "numeric_features": numeric_features,
        "categorical_features": categorical_features,
        "feature_labels": FEATURE_LABELS,
    })


@app.route("/api/samples")
def samples():
    """Return all sample profile cards (no raw data, just metadata)."""
    return jsonify([
        {k: v for k, v in p.items() if k != "data"}
        for p in SAMPLE_PROFILES
    ])


@app.route("/api/sample/<int:profile_id>")
def sample(profile_id: int):
    """Run prediction on a pre-defined sample profile."""
    profile = next((p for p in SAMPLE_PROFILES if p["id"] == profile_id), None)
    if not profile:
        return jsonify({"error": f"Profile {profile_id} not found."}), 404

    record = profile["data"].copy()
    try:
        result = _predict_record(record) if model_loaded else _predict_demo(record)
        result["profile_name"] = profile["name"]
        result["profile_title"] = profile["title"]
        result["record"] = record
        return jsonify(result)
    except Exception as e:
        logger.error(f"Sample prediction error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/predict", methods=["POST"])
def predict():
    """Handle prediction from JSON body or CSV file upload."""
    try:
        record = {}

        # ── CSV Upload ───────────────────────────────────────────────────────
        if "csv_file" in request.files and request.files["csv_file"].filename:
            csv_file = request.files["csv_file"]
            if not csv_file.filename.lower().endswith(".csv"):
                return jsonify({"error": "Only CSV files are accepted."}), 400
            try:
                df = pd.read_csv(csv_file)
            except Exception:
                return jsonify({"error": "Could not read the uploaded file. Ensure it is a valid CSV."}), 400
            if df.empty:
                return jsonify({"error": "The uploaded CSV file is empty."}), 400
            batch, total, fn_rows, has_gt = _predict_batch_chunked(df, chunk_size=1000)
            fp_count = sum(1 for r in batch if r.get("actual_label") == 0) if has_gt else 0
            return jsonify({
                "results":              batch,
                "total_records":        total,
                "malicious_count":      len(batch),
                "has_ground_truth":     has_gt,
                "false_positive_count": fp_count,
                "false_negative_count": len(fn_rows),
                "false_negatives":      fn_rows,
            })

        # ── JSON Body ────────────────────────────────────────────────────────
        elif request.is_json:
            body = request.get_json(force=True)
            for feat in numeric_features:
                try:
                    record[feat] = float(body.get(feat, 0))
                except (ValueError, TypeError):
                    record[feat] = 0.0
            for feat in categorical_features:
                record[feat] = str(body.get(feat, "unknown"))

        else:
            return jsonify({"error": "Send a JSON body or upload a CSV file."}), 400

        result = _predict_record(record) if model_loaded else _predict_demo(record)
        result["record"] = record
        return jsonify(result)

    except Exception as e:
        logger.error(f"Prediction error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/train", methods=["POST"])
def train_model_endpoint():
    """
    Train the Random Forest model from an uploaded CSV file.
    Returns accuracy, precision, recall, F1-score, and confusion matrix.
    """
    if "csv_file" not in request.files or not request.files["csv_file"].filename:
        return jsonify({"error": "Upload a CSV file with field name 'csv_file'."}), 400

    csv_file = request.files["csv_file"]
    if not csv_file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only CSV files are accepted."}), 400

    try:
        df = pd.read_csv(csv_file)
    except Exception:
        return jsonify({"error": "Could not read the uploaded file. Ensure it is a valid CSV."}), 400

    if df.empty:
        return jsonify({"error": "The uploaded CSV file is empty."}), 400

    if "is_malicious" not in df.columns:
        return jsonify({"error": "CSV must contain an 'is_malicious' column (0 or 1) as the target label."}), 400

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, confusion_matrix, classification_report,
        )
        from preprocess import (
            build_preprocessor, prepare_features,
            compute_thresholds, save_preprocessor,
        )

        X, y, num_feats, cat_feats = prepare_features(df)

        thresholds = compute_thresholds(X, y, num_feats)

        preprocessor_new = build_preprocessor(num_feats, cat_feats)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=23, stratify=y
        )

        X_train_t = preprocessor_new.fit_transform(X_train)
        X_test_t  = preprocessor_new.transform(X_test)

        rf_params = {
            "n_estimators": 200,
            "max_depth": None,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "class_weight": "balanced",
            "random_state": 23,
            "n_jobs": -1,
        }
        rf = RandomForestClassifier(**rf_params)
        rf.fit(X_train_t, y_train)

        y_pred = rf.predict(X_test_t)

        accuracy  = float(accuracy_score(y_test, y_pred))
        precision = float(precision_score(y_test, y_pred, zero_division=0))
        recall    = float(recall_score(y_test, y_pred, zero_division=0))
        f1        = float(f1_score(y_test, y_pred, zero_division=0))
        cm        = confusion_matrix(y_test, y_pred).tolist()
        report    = classification_report(
            y_test, y_pred, target_names=["Normal (0)", "Malicious (1)"]
        )

        # Persist the newly trained model so it is immediately usable
        os.makedirs(MODELS_DIR, exist_ok=True)
        joblib.dump(rf, MODEL_PATH)
        save_preprocessor(preprocessor_new, PREPROCESSOR_PATH)

        if cat_feats:
            cat_enc = preprocessor_new.named_transformers_["cat"]["encoder"]
            cat_names = cat_enc.get_feature_names_out(cat_feats).tolist()
        else:
            cat_names = []

        feature_importances = {
            feat: round(float(imp), 6)
            for feat, imp in zip(num_feats + cat_names, rf.feature_importances_)
        }

        metadata = {
            "numeric_features": num_feats,
            "categorical_features": cat_feats,
            "all_feature_names": num_feats + cat_names,
            "feature_importances": feature_importances,
            "decision_threshold": 0.5,
            "recall_target": 0.9,
            "thresholds": thresholds,
        }
        with open(MODEL_METADATA_PATH, "w") as fh:
            json.dump(metadata, fh, indent=2)

        # Reload global model state
        load_model()

        logger.info("Model retrained via /api/train – accuracy=%.4f  f1=%.4f", accuracy, f1)

        return jsonify({
            "status": "trained",
            "training_records": int(len(X_train)),
            "test_records": int(len(X_test)),
            "accuracy":  round(accuracy, 4),
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1":        round(f1, 4),
            "confusion_matrix": cm,
            "classification_report": report,
        })

    except Exception as exc:
        logger.error(f"Training error: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/malicious", methods=["GET"])
def get_malicious():
    """Return the previously saved malicious results JSON file."""
    if not os.path.exists(MALICIOUS_RESULTS_PATH):
        return jsonify({"error": "No saved results found. Upload a CSV first."}), 404
    try:
        with open(MALICIOUS_RESULTS_PATH, "r") as fh:
            data = json.load(fh)
        return jsonify(data)
    except Exception as e:
        logger.error(f"Load malicious results error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/explain", methods=["POST"])
def explain():
    """
    Lazy-load full explainability for a single record.
    Used by the batch CSV table when a row is expanded.
    Expects JSON body: the raw record dict.
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Send a JSON body with the record."}), 400
        record_raw = request.get_json(force=True)
        rec = {}
        for feat in numeric_features:
            try:
                rec[feat] = float(record_raw.get(feat, 0))
            except (ValueError, TypeError):
                rec[feat] = 0.0
        for feat in categorical_features:
            rec[feat] = str(record_raw.get(feat, "unknown"))

        result = _predict_record(rec) if model_loaded else _predict_demo(rec)
        result["record"] = rec
        return jsonify(result)
    except Exception as e:
        logger.error(f"Explain error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ── Serve React App ──────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    """Serve the React build for all non-API, non-static routes."""
    target = os.path.join(BUILD_DIR, path)
    if path != "" and os.path.exists(target):
        return send_from_directory(BUILD_DIR, path)
    return send_from_directory(BUILD_DIR, "index.html")


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000, threaded=True)
