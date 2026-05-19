
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


sys.path.insert(0, os.path.dirname(__file__))

from preprocess import (
    load_dataset,
    build_preprocessor,
    prepare_features,
    compute_thresholds,
    save_preprocessor,
    FEATURE_LABELS,
)


DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "insider_threat_clean_dataset.csv")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.pkl")
PREPROCESSOR_PATH = os.path.join(MODELS_DIR, "preprocessor.pkl")
THRESHOLDS_PATH = os.path.join(MODELS_DIR, "thresholds.json")  
FEATURE_NAMES_PATH = os.path.join(MODELS_DIR, "feature_names.json") 
MODEL_METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")
METRICS_PATH = os.path.join(MODELS_DIR, "metrics_report.txt")
CONFUSION_MATRIX_PATH = os.path.join(MODELS_DIR, "confusion_matrix.png")
FEATURE_IMPORTANCE_PATH = os.path.join(MODELS_DIR, "feature_importance.png")


RF_PARAMS = {
    "n_estimators": 200,
    "max_depth": None,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "random_state": 71,  
    "n_jobs": -1,
}

TEST_SIZE = 0.20
RANDOM_STATE = 71  


def train_and_evaluate():
    
    os.makedirs(MODELS_DIR, exist_ok=True)

   
    
    print("COS720 – Insider Threat Detection System – Training")
    

    df = load_dataset(DATA_PATH)

    print(f"\n Class distribution:")
    counts = df["is_malicious"].value_counts()
    for label, count in counts.items():
        label_str = "Malicious" if label == 1 else "Normal"
        pct = count / len(df) * 100
        print(f"       {label_str} ({label}): {count:,} records ({pct:.2f}%)")

  
    X, y, numeric_features, categorical_features = prepare_features(df)
    print(f"\n Numeric features  ({len(numeric_features)}): {numeric_features}")
    print(f"Categorical features ({len(categorical_features)}): {categorical_features}")

   
    thresholds = compute_thresholds(X, y, numeric_features)

    
    preprocessor = build_preprocessor(numeric_features, categorical_features)

   
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\nTraining set: {len(X_train):,} records")
    print(f"Test set:     {len(X_test):,} records")

  
    X_train_t = preprocessor.fit_transform(X_train)
    X_test_t = preprocessor.transform(X_test)

    
    if categorical_features:
        cat_encoder = preprocessor.named_transformers_["cat"]["encoder"]
        cat_feature_names = cat_encoder.get_feature_names_out(categorical_features).tolist()
    else:
        cat_feature_names = []
    all_feature_names = numeric_features + cat_feature_names

    print(f"\nTotal transformed features: {len(all_feature_names)}")

    # ── 7. Train Random Forest ───────────────────────────────────────────────
    print("\nTraining Random Forest Classifier...")
    print(f"       Parameters: {RF_PARAMS}")
    rf = RandomForestClassifier(**RF_PARAMS)
    rf.fit(X_train_t, y_train)
    print("Training complete.")

    # ── 8. Evaluate ─────────────────────────────────────────────────────────
    y_pred = rf.predict(X_test_t)
    y_prob = rf.predict_proba(X_test_t)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(
        y_test, y_pred, target_names=["Normal (0)", "Malicious (1)"]
    )

  
    with open(METRICS_PATH, "w") as f:
        f.write("COS720 – Insider Threat Detection – Model Evaluation Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Model: Random Forest Classifier\n")
        f.write(f"Training records: {len(X_train):,}\n")
        f.write(f"Test records:     {len(X_test):,}\n\n")
        f.write(f"Accuracy  : {accuracy:.4f} ({accuracy * 100:.2f}%)\n")
        f.write(f"Precision : {precision:.4f}\n")
        f.write(f"Recall    : {recall:.4f}\n")
        f.write(f"F1-Score  : {f1:.4f}\n\n")
        f.write(f"Confusion Matrix:\n")
        f.write(f"  TN={cm[0,0]:,}  FP={cm[0,1]:,}\n")
        f.write(f"  FN={cm[1,0]:,}  TP={cm[1,1]:,}\n\n")
        f.write(f"Classification Report:\n{report}\n")
        f.write(f"\nHyperparameters: {RF_PARAMS}\n")


    plt.figure(figsize=(7, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt=",",
        cmap="Blues",
        xticklabels=["Normal", "Malicious"],
        yticklabels=["Normal", "Malicious"],
        linewidths=0.5,
    )
    plt.title("Confusion Matrix – Random Forest Classifier", fontsize=14, fontweight="bold")
    plt.ylabel("Actual Label", fontsize=12)
    plt.xlabel("Predicted Label", fontsize=12)
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH, dpi=150)
    plt.close()
   

   
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]
    top_n = min(15, len(all_feature_names))

   
    display_names = []
    for feat in [all_feature_names[i] for i in indices[:top_n]]:
        label = FEATURE_LABELS.get(feat, feat.replace("_", " ").title())
        display_names.append(label)

    plt.figure(figsize=(10, 6))
    colors = plt.cm.RdYlGn_r(np.linspace(0.1, 0.9, top_n))
    plt.barh(
        range(top_n - 1, -1, -1),
        [importances[indices[i]] for i in range(top_n)],
        color=colors,
        edgecolor="grey",
        linewidth=0.5,
    )
    plt.yticks(range(top_n - 1, -1, -1), display_names, fontsize=9)
    plt.xlabel("Mean Decrease in Impurity (Feature Importance)", fontsize=11)
    plt.title("Top Feature Importances – Random Forest", fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(FEATURE_IMPORTANCE_PATH, dpi=150)
    plt.close()
    print(f"Feature importance chart saved to {FEATURE_IMPORTANCE_PATH}")

    
    joblib.dump(rf, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

    save_preprocessor(preprocessor, PREPROCESSOR_PATH)

    metadata = {
        "numeric_features": numeric_features,
        "categorical_features": categorical_features,
        "all_feature_names": all_feature_names,
        "feature_importances": dict(
            zip(all_feature_names, rf.feature_importances_.tolist())
        ),
        "decision_threshold": 0.5,
        "recall_target": 0.9,
        "thresholds": thresholds,
    }
    with open(MODEL_METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to {MODEL_METADATA_PATH}")

    print("\n" + "=" * 60)
    print("Training pipeline complete. All files saved to prototype/models/")
    print("=" * 60)


if __name__ == "__main__":
    train_and_evaluate()
