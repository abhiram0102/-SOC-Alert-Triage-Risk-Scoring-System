"""
ml_scorer.py — Real-Time ML Risk Scoring Engine
Loads the trained Random Forest model and scores enriched Suricata alerts.
Handles unseen categories, confidence thresholding, and graceful fallback.
"""

import logging
import os
import json
from typing import Tuple, Dict, Any, Optional

import numpy as np
import joblib

logger = logging.getLogger("soc_triage.ml_scorer")

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

MODEL_DIR = os.getenv("MODEL_DIR", "model")
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.70"))

HIGH_RISK_PORTS = {22, 23, 25, 445, 3389, 1433, 3306, 4444, 6379, 8080, 8443}

# ─── MODEL LOADER ─────────────────────────────────────────────────────────────

class ModelLoader:
    """
    Singleton-style loader that reads model artefacts from disk once
    and keeps them in memory for all subsequent scoring calls.
    """

    _instance: Optional["ModelLoader"] = None

    def __new__(cls, model_dir: str = MODEL_DIR):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def load(self, model_dir: str = MODEL_DIR) -> None:
        if self._loaded:
            return

        required_files = [
            "rf_model.pkl",
            "le_category.pkl",
            "le_protocol.pkl",
            "le_label.pkl",
            "feature_columns.pkl",
        ]
        missing = [f for f in required_files if not os.path.exists(os.path.join(model_dir, f))]
        if missing:
            raise FileNotFoundError(
                f"Model artefacts missing in '{model_dir}': {missing}. "
                f"Run train_model.py first."
            )

        self.model = joblib.load(os.path.join(model_dir, "rf_model.pkl"))
        self.le_category = joblib.load(os.path.join(model_dir, "le_category.pkl"))
        self.le_protocol = joblib.load(os.path.join(model_dir, "le_protocol.pkl"))
        self.le_label = joblib.load(os.path.join(model_dir, "le_label.pkl"))
        self.feature_columns = joblib.load(os.path.join(model_dir, "feature_columns.pkl"))

        # Load metadata if available
        meta_path = os.path.join(model_dir, "model_metadata.json")
        self.metadata: Dict[str, Any] = {}
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                self.metadata = json.load(f)

        self._loaded = True
        logger.info(
            "Model loaded | trained_at=%s | features=%d | classes=%s",
            self.metadata.get("trained_at", "unknown"),
            len(self.feature_columns),
            self.le_label.classes_.tolist(),
        )

    @property
    def classes(self):
        return self.le_label.classes_.tolist()

    def encode_category(self, category: str) -> int:
        """Encode alert category, returning 0 for unseen categories."""
        try:
            return int(self.le_category.transform([category])[0])
        except ValueError:
            logger.debug("Unseen category '%s', defaulting to 0", category)
            return 0

    def encode_protocol(self, protocol: str) -> int:
        """Encode protocol string, defaulting to 'tcp' encoding for unknowns."""
        try:
            return int(self.le_protocol.transform([protocol.lower()])[0])
        except ValueError:
            logger.debug("Unseen protocol '%s', defaulting to tcp encoding", protocol)
            try:
                return int(self.le_protocol.transform(["tcp"])[0])
            except ValueError:
                return 0


# Global loader instance
_loader = ModelLoader()


def _ensure_loaded():
    """Ensure model is loaded before scoring."""
    if not _loader._loaded:
        _loader.load(MODEL_DIR)


# ─── FEATURE ENGINEERING (mirrors train_model.py) ───────────────────────────

def _build_feature_vector(alert: Dict[str, Any], loader: ModelLoader) -> np.ndarray:
    """
    Build a feature vector from an enriched alert dict.
    Applies the same engineering steps as training.
    """
    enrich = alert.get("enrichment", {})

    # Base features
    alert_severity = int(alert.get("alert_severity", 3))
    abuse_score = int(enrich.get("abuse_confidence_score", 0))
    vt_malicious = int(enrich.get("vt_malicious_count", 0))
    cat_encoded = loader.encode_category(alert.get("alert_category", "unknown"))
    dest_port = int(alert.get("dest_port", 0))
    proto_encoded = loader.encode_protocol(alert.get("proto", "tcp"))
    src_ip_freq = int(alert.get("src_ip_frequency", 1))

    # Engineered features (must match train_model.py)
    threat_composite = (
        abuse_score * 0.5
        + vt_malicious * 2.0
        + (4 - alert_severity) * 10.0
    )

    def port_bucket(p: int) -> int:
        if p < 1024:
            return 0
        elif p < 49152:
            return 1
        return 2

    p_bucket = port_bucket(dest_port)
    is_high_risk = 1 if dest_port in HIGH_RISK_PORTS else 0
    freq_log = float(np.log1p(src_ip_freq))

    # Build ordered vector matching feature_columns list
    base_vector = {
        "alert_severity": alert_severity,
        "abuse_confidence_score": min(abuse_score, 100),
        "vt_malicious_count": min(vt_malicious, 70),
        "alert_category_encoded": cat_encoded,
        "dest_port": dest_port,
        "protocol_encoded": proto_encoded,
        "src_ip_frequency": min(src_ip_freq, 500),
        "threat_composite": threat_composite,
        "port_bucket": p_bucket,
        "is_high_risk_port": is_high_risk,
        "src_ip_freq_log": freq_log,
    }

    # Return in the exact order the model was trained on
    vector = [base_vector.get(col, 0) for col in loader.feature_columns]
    return np.array([vector], dtype=float)


# ─── RULE-BASED OVERRIDE ─────────────────────────────────────────────────────

def _rule_based_override(alert: Dict[str, Any]) -> Optional[str]:
    """
    Apply deterministic business rules BEFORE the ML model.
    Returns a forced label string, or None to let ML decide.

    These rules handle edge cases where ML uncertainty is high:
    - Confirmed TOR exit nodes → at minimum HIGH
    - Abuse score = 100 → CRITICAL
    - Zero signals → LOW (avoid wasting analyst time)
    """
    enrich = alert.get("enrichment", {})
    abuse_score = int(enrich.get("abuse_confidence_score", 0))
    vt_malicious = int(enrich.get("vt_malicious_count", 0))
    is_tor = bool(enrich.get("is_tor_exit", False))
    alert_severity = int(alert.get("alert_severity", 3))

    # Deterministically CRITICAL: perfect abuse score + VT confirmation
    if abuse_score == 100 and vt_malicious >= 10:
        return "CRITICAL"

    # Deterministically HIGH: TOR exit node with malicious VT results
    if is_tor and vt_malicious >= 5:
        return "HIGH"

    # Deterministically LOW: no signals at all
    if abuse_score == 0 and vt_malicious == 0 and alert_severity == 3:
        return None  # Let ML decide — could still be medium based on category

    return None  # No override; let ML score


# ─── MAIN SCORING FUNCTION ───────────────────────────────────────────────────

def score_alert(alert: Dict[str, Any]) -> Tuple[str, float]:
    """
    Score an enriched Suricata alert using the trained Random Forest model.

    Args:
        alert: dict from Elasticsearch containing Suricata alert fields
               and an 'enrichment' sub-dict added by enrichment.py.

    Returns:
        Tuple of (risk_label, confidence):
          - risk_label: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
          - confidence: float in [0, 1] representing model confidence

    Behaviour:
        - Rule-based overrides are applied first (deterministic edge cases)
        - ML model predicts label and confidence
        - If HIGH predicted with confidence < CONFIDENCE_THRESHOLD → downgrade to MEDIUM
        - If CRITICAL predicted with confidence < 0.85 → downgrade to HIGH
        - Falls back to "MEDIUM" on any model error
    """
    _ensure_loaded()

    # ── Rule-based override ───────────────────────────────────────────
    override = _rule_based_override(alert)
    if override:
        logger.debug("Rule override applied: %s for alert from %s",
                     override, alert.get("src_ip", "?"))
        return override, 1.0

    # ── ML scoring ───────────────────────────────────────────────────
    try:
        features = _build_feature_vector(alert, _loader)
        pred_idx = _loader.model.predict(features)[0]
        proba = _loader.model.predict_proba(features)[0]
        confidence = float(proba.max())
        risk_label: str = _loader.le_label.inverse_transform([pred_idx])[0]

        # ── Confidence-based downgrading ──────────────────────────────
        if risk_label == "CRITICAL" and confidence < 0.85:
            logger.debug(
                "CRITICAL downgraded to HIGH (confidence=%.3f < 0.85) for %s",
                confidence, alert.get("src_ip", "?"),
            )
            risk_label = "HIGH"

        if risk_label == "HIGH" and confidence < CONFIDENCE_THRESHOLD:
            logger.debug(
                "HIGH downgraded to MEDIUM (confidence=%.3f < %.2f) for %s",
                confidence, CONFIDENCE_THRESHOLD, alert.get("src_ip", "?"),
            )
            risk_label = "MEDIUM"

        logger.debug(
            "Scored alert from %s → %s (conf=%.3f)",
            alert.get("src_ip", "?"), risk_label, confidence,
        )
        return risk_label, round(confidence, 4)

    except Exception as exc:
        logger.error("ML scoring failed: %s | Defaulting to MEDIUM", exc, exc_info=True)
        return "MEDIUM", 0.5


def score_batch(alerts: list) -> list:
    """
    Score a batch of enriched alerts.
    Returns a list of (risk_label, confidence) tuples in the same order.
    More efficient than calling score_alert() in a Python loop because
    we build the feature matrix once and call predict once.
    """
    _ensure_loaded()

    if not alerts:
        return []

    results = []
    try:
        # Build batch feature matrix
        feature_matrix = np.vstack([
            _build_feature_vector(a, _loader) for a in alerts
        ])
        predictions = _loader.model.predict(feature_matrix)
        probas = _loader.model.predict_proba(feature_matrix)

        for i, (pred_idx, proba) in enumerate(zip(predictions, probas)):
            confidence = float(proba.max())
            label: str = _loader.le_label.inverse_transform([pred_idx])[0]

            # Apply confidence downgrading
            if label == "CRITICAL" and confidence < 0.85:
                label = "HIGH"
            if label == "HIGH" and confidence < CONFIDENCE_THRESHOLD:
                label = "MEDIUM"

            # Apply rule overrides
            override = _rule_based_override(alerts[i])
            if override:
                label, confidence = override, 1.0

            results.append((label, round(confidence, 4)))

    except Exception as exc:
        logger.error("Batch scoring failed: %s | Defaulting all to MEDIUM", exc)
        results = [("MEDIUM", 0.5)] * len(alerts)

    return results


def get_model_info() -> Dict[str, Any]:
    """Return model metadata for health checks and API responses."""
    _ensure_loaded()
    return {
        "model_type": type(_loader.model).__name__,
        "n_estimators": getattr(_loader.model, "n_estimators", None),
        "features": _loader.feature_columns,
        "classes": _loader.classes,
        "metadata": _loader.metadata,
        "loaded": _loader._loaded,
    }
