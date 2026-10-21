"""
train_model.py — ML Training Pipeline for SOC Alert Risk Scoring
Trains a Random Forest classifier to label alerts as LOW/MEDIUM/HIGH/CRITICAL.
Includes feature engineering, cross-validation, feature importance, and model persistence.

Run: python3 train_model.py [--data data/training_data.csv] [--output model/]
"""

import os
import sys
import logging
import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    accuracy_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# ─── LOGGING ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("soc_triage.train_model")

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

FEATURE_COLUMNS = [
    "alert_severity",
    "abuse_confidence_score",
    "vt_malicious_count",
    "alert_category_encoded",
    "dest_port",
    "protocol_encoded",
    "src_ip_frequency",
]

LABEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ─── FEATURE ENGINEERING ─────────────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply feature engineering transformations:
    - Cap extreme values to reduce outlier influence
    - Add derived interaction features
    - Normalize port numbers into buckets
    """
    df = df.copy()

    # Cap frequency outliers at 99th percentile
    freq_cap = df["src_ip_frequency"].quantile(0.99)
    df["src_ip_frequency"] = df["src_ip_frequency"].clip(upper=freq_cap)

    # Cap VT and abuse scores
    df["vt_malicious_count"] = df["vt_malicious_count"].clip(upper=70)
    df["abuse_confidence_score"] = df["abuse_confidence_score"].clip(upper=100)

    # Derived: threat signal composite
    df["threat_composite"] = (
        df["abuse_confidence_score"] * 0.5
        + df["vt_malicious_count"] * 2.0
        + (4 - df["alert_severity"]) * 10.0
    )

    # Port bucket: well-known=0, registered=1, dynamic=2
    def port_bucket(p):
        if p < 1024:
            return 0
        elif p < 49152:
            return 1
        else:
            return 2

    df["port_bucket"] = df["dest_port"].apply(port_bucket)

    # High-risk port flag
    HIGH_RISK_PORTS = {22, 23, 25, 445, 3389, 1433, 3306, 4444, 6379}
    df["is_high_risk_port"] = df["dest_port"].isin(HIGH_RISK_PORTS).astype(int)

    # Frequency log transform (stabilizes scale)
    df["src_ip_freq_log"] = np.log1p(df["src_ip_frequency"])

    return df


# ─── TRAINING PIPELINE ───────────────────────────────────────────────────────

def load_and_validate(data_path: str) -> pd.DataFrame:
    """Load the CSV and validate required columns exist."""
    logger.info("Loading training data from: %s", data_path)
    df = pd.read_csv(data_path)
    required = [
        "alert_severity", "abuse_confidence_score", "vt_malicious_count",
        "alert_category", "dest_port", "protocol", "src_ip_frequency", "risk_label",
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Training data missing columns: {missing}")

    logger.info("Loaded %d samples | Labels: %s",
                len(df), df["risk_label"].value_counts().to_dict())
    return df


def encode_features(df: pd.DataFrame):
    """
    Encode categorical string features into integers.
    Returns: (df_encoded, le_category, le_protocol, le_label)
    """
    le_category = LabelEncoder()
    le_protocol = LabelEncoder()
    le_label = LabelEncoder()

    # Fit encoders
    all_categories = list(df["alert_category"].fillna("unknown").unique()) + ["unknown"]
    all_protocols = list(df["protocol"].fillna("tcp").unique()) + ["tcp", "udp", "icmp"]
    all_labels = LABEL_ORDER  # Use fixed order for deterministic mapping

    le_category.fit(sorted(set(all_categories)))
    le_protocol.fit(sorted(set(all_protocols)))
    le_label.fit(all_labels)

    df = df.copy()
    df["alert_category_encoded"] = le_category.transform(df["alert_category"].fillna("unknown"))
    df["protocol_encoded"] = le_protocol.transform(df["protocol"].fillna("tcp"))
    df["risk_label_encoded"] = le_label.transform(df["risk_label"])

    return df, le_category, le_protocol, le_label


def train(data_path: str, output_dir: str):
    """Full training pipeline with evaluation."""
    os.makedirs(output_dir, exist_ok=True)

    # ── Load and prepare ──────────────────────────────────────────────
    df = load_and_validate(data_path)
    df, le_category, le_protocol, le_label = encode_features(df)
    df = engineer_features(df)

    # Extended feature set including engineered features
    extended_features = FEATURE_COLUMNS + [
        "threat_composite", "port_bucket", "is_high_risk_port", "src_ip_freq_log"
    ]

    X = df[extended_features].fillna(0)
    y = df["risk_label_encoded"]

    logger.info("Feature matrix shape: %s", X.shape)

    # ── Train/test split ──────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info("Train: %d | Test: %d", len(X_train), len(X_test))

    # ── Random Forest ─────────────────────────────────────────────────
    logger.info("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,       # Use all CPU cores
        oob_score=True,  # Out-of-bag score for free validation
    )
    model.fit(X_train, y_train)
    logger.info("OOB Score: %.4f", model.oob_score_)

    # ── Cross-Validation ──────────────────────────────────────────────
    logger.info("Running 5-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    logger.info(
        "CV Accuracy: %.4f ± %.4f (min: %.4f, max: %.4f)",
        cv_scores.mean(), cv_scores.std(), cv_scores.min(), cv_scores.max(),
    )

    # ── Evaluation ────────────────────────────────────────────────────
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    label_names = le_label.classes_
    acc = accuracy_score(y_test, y_pred)
    logger.info("Test Accuracy: %.4f", acc)

    print("\n" + "=" * 60)
    print("CLASSIFICATION REPORT")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=label_names))

    print("CONFUSION MATRIX")
    print("=" * 60)
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(cm, index=label_names, columns=label_names)
    print(cm_df)
    print()

    # Multi-class AUC (one-vs-rest)
    try:
        auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro")
        print(f"Macro ROC-AUC: {auc:.4f}")
    except Exception:
        pass

    # ── Feature Importance ───────────────────────────────────────────
    print("\nFEATURE IMPORTANCES")
    print("=" * 60)
    importances = sorted(
        zip(extended_features, model.feature_importances_),
        key=lambda x: -x[1],
    )
    for feat, imp in importances:
        bar = "█" * int(imp * 50)
        print(f"  {feat:<35} {imp:.4f}  {bar}")
    print()

    # ── Save artefacts ────────────────────────────────────────────────
    model_path = os.path.join(output_dir, "rf_model.pkl")
    joblib.dump(model, model_path, compress=3)
    joblib.dump(le_category, os.path.join(output_dir, "le_category.pkl"))
    joblib.dump(le_protocol, os.path.join(output_dir, "le_protocol.pkl"))
    joblib.dump(le_label, os.path.join(output_dir, "le_label.pkl"))
    joblib.dump(extended_features, os.path.join(output_dir, "feature_columns.pkl"))

    # Save training metadata
    metadata = {
        "trained_at": pd.Timestamp.now().isoformat(),
        "n_samples": int(len(df)),
        "n_features": int(len(extended_features)),
        "features": extended_features,
        "classes": list(label_names),
        "oob_score": float(model.oob_score_),
        "cv_accuracy_mean": float(cv_scores.mean()),
        "cv_accuracy_std": float(cv_scores.std()),
        "test_accuracy": float(acc),
        "n_estimators": model.n_estimators,
        "max_depth": model.max_depth,
    }
    import json
    with open(os.path.join(output_dir, "model_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Model and encoders saved to: %s", output_dir)
    logger.info("Training complete. Test accuracy: %.4f", acc)

    return model


# ─── CLI ENTRYPOINT ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SOC Alert Risk Scoring Model")
    parser.add_argument(
        "--data",
        default="data/training_data.csv",
        help="Path to training CSV (default: data/training_data.csv)",
    )
    parser.add_argument(
        "--output",
        default="model",
        help="Directory to save model artefacts (default: model/)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.data):
        logger.info("Training data not found. Generating synthetic data...")
        sys.path.insert(0, "ml")
        from generate_training_data import generate_dataset
        os.makedirs("data", exist_ok=True)
        df = generate_dataset()
        df.to_csv(args.data, index=False)
        logger.info("Synthetic training data written to %s", args.data)

    train(args.data, args.output)
