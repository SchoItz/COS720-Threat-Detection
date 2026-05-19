
import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline


NUMERIC_FEATURES = [
    "employee_seniority_years",
    "total_files_burned",
    "burned_from_other",
    "num_printed_pages_off_hours",
    "total_printed_pages",
    "num_entries",
    "late_exit_flag",
    "entry_during_weekend",
    "trip_day_number",
    "hostility_country_level",
    "has_criminal_record",
]

CATEGORICAL_FEATURES = [
    "employee_department",
    "employee_classification",
    "is_contractor",
]

TARGET_COLUMN = "is_malicious"

FEATURE_LABELS = {
    "total_files_burned": "Files Burned to External Media",
    "burned_from_other": "Files Burned from Unusual Locations",
    "num_printed_pages_off_hours": "Off Hours Pages Printed",
    "total_printed_pages": "Pages Printed Today",
    "num_entries": "Amount of Building Entries",
    "late_exit_flag": "Late Exit",
    "entry_during_weekend": "Weekend Building Access",
    "employee_seniority_years": "Employee Seniority in years",
    "trip_day_number": "Days on Business Trip",
    "hostility_country_level": "Destination Country Risk Level",
    "has_criminal_record": "Criminal Record on File",
    "employee_department": "Department",
    "employee_classification": "Security Clearance Level",
    "is_contractor": "Contractor vs Permanent",
}


def load_dataset(filepath: str) -> pd.DataFrame:
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"Dataset not found at '{filepath}'.\n"
        )

    df = pd.read_csv(filepath)
    print(f"Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns")

    # Validate target column
    if TARGET_COLUMN not in df.columns:
        raise ValueError(
            f"Target column '{TARGET_COLUMN}' not found in dataset.\n"
            f"Available columns: {list(df.columns)}"
        )

    # Identify which expected features are available
    available_numeric = [f for f in NUMERIC_FEATURES if f in df.columns]
    available_categorical = [f for f in CATEGORICAL_FEATURES if f in df.columns]

    missing = (
        set(NUMERIC_FEATURES + CATEGORICAL_FEATURES)
        - set(available_numeric + available_categorical)
    )
    if missing:
        print(f"[WARN] The following expected features were not found: {missing}")
        print("[WARN] Training will proceed with available features only.")

    return df


def build_preprocessor(numeric_features: list, categorical_features: list) -> ColumnTransformer:
    numeric_pipeline = Pipeline([
        ("scaler", StandardScaler()),
    ])

    categorical_pipeline = Pipeline([
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_pipeline, numeric_features),
            ("cat", categorical_pipeline, categorical_features),
        ],
        remainder="drop",
    )
    return preprocessor


def prepare_features(df: pd.DataFrame) -> tuple:
    available_numeric = [f for f in NUMERIC_FEATURES if f in df.columns]
    available_categorical = [f for f in CATEGORICAL_FEATURES if f in df.columns]

    X = df[available_numeric + available_categorical].copy()
    y = df[TARGET_COLUMN].copy()

    # Handle any missing values (fill numeric with median, categorical with mode)
    for col in available_numeric:
        if X[col].isnull().any():
            X[col].fillna(X[col].median(), inplace=True)

    for col in available_categorical:
        if X[col].isnull().any():
            X[col].fillna(X[col].mode()[0], inplace=True)

    return X, y, available_numeric, available_categorical


def compute_thresholds(X: pd.DataFrame, y: pd.Series, numeric_features: list) -> dict:
    normal_records = X[y == 0]
    thresholds = {}
    for col in numeric_features:
        if col in X.columns:
            thresholds[col] = {
                "normal_mean": float(normal_records[col].mean()),
                "normal_std": float(normal_records[col].std()),
                "normal_75th": float(normal_records[col].quantile(0.75)),
                "normal_95th": float(normal_records[col].quantile(0.95)),
                "overall_max": float(X[col].max()),
            }
    return thresholds


def save_preprocessor(preprocessor: ColumnTransformer, path: str) -> None:
    """Save fitted preprocessor to disk."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(preprocessor, path)
    print(f"[INFO] Preprocessor saved to {path}")


def load_preprocessor(path: str) -> ColumnTransformer:
    """Load fitted preprocessor from disk."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Preprocessor not found at '{path}'. Run train_model.py first.")
    return joblib.load(path)


def transform_single_record(record: dict, preprocessor: ColumnTransformer,
                             numeric_features: list, categorical_features: list) -> np.ndarray:

    row = {}
    for feat in numeric_features:
        row[feat] = float(record.get(feat, 0))
    for feat in categorical_features:
        row[feat] = str(record.get(feat, "unknown"))

    df_row = pd.DataFrame([row])
    return preprocessor.transform(df_row)
