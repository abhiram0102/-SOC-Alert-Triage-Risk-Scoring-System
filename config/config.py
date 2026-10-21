"""
config.py — Central configuration for the SOC Alert Triage System
Loads all settings from environment variables via .env file.
"""

import os
import logging
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv()

# ─── LOGGING SETUP ───────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.getenv("LOG_FILE", "logs/pipeline.log")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, mode="a"),
    ],
)

logger = logging.getLogger("soc_triage.config")

# ─── THREAT INTELLIGENCE API KEYS ────────────────────────────────────────────

ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

if not ABUSEIPDB_API_KEY:
    logger.warning("ABUSEIPDB_API_KEY is not set. AbuseIPDB enrichment will return 0.")
if not VIRUSTOTAL_API_KEY:
    logger.warning("VIRUSTOTAL_API_KEY is not set. VirusTotal enrichment will return 0.")

# ─── ELASTICSEARCH CONFIGURATION ─────────────────────────────────────────────

ES_HOST: str = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ES_INDEX: str = os.getenv("ELASTICSEARCH_INDEX", "suricata-alerts-*")
ES_USERNAME: str = os.getenv("ELASTICSEARCH_USERNAME", "")
ES_PASSWORD: str = os.getenv("ELASTICSEARCH_PASSWORD", "")
ES_VERIFY_CERTS: bool = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"

# ─── REDIS CACHE CONFIGURATION ───────────────────────────────────────────────

REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")
USE_REDIS: bool = os.getenv("USE_REDIS", "false").lower() == "true"

# ─── PIPELINE SETTINGS ───────────────────────────────────────────────────────

POLL_INTERVAL: int = int(os.getenv("POLL_INTERVAL", "30"))          # seconds
BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "50"))                # alerts per cycle
FREQ_WINDOW_MINUTES: int = int(os.getenv("FREQ_WINDOW_MINUTES", "60"))  # sliding window

# ─── CACHING ─────────────────────────────────────────────────────────────────

CACHE_TTL: int = int(os.getenv("CACHE_TTL", "3600"))               # 1 hour in seconds

# ─── API RATE LIMITING ───────────────────────────────────────────────────────

ABUSEIPDB_RATE_LIMIT_DELAY: float = float(os.getenv("ABUSEIPDB_RATE_LIMIT_DELAY", "0.1"))   # 100ms
VIRUSTOTAL_RATE_LIMIT_DELAY: float = float(os.getenv("VIRUSTOTAL_RATE_LIMIT_DELAY", "15.0"))  # 4 req/min free tier
API_MAX_RETRIES: int = int(os.getenv("API_MAX_RETRIES", "3"))
API_RETRY_BACKOFF: float = float(os.getenv("API_RETRY_BACKOFF", "2.0"))  # exponential base

# ─── ML MODEL SETTINGS ───────────────────────────────────────────────────────

MODEL_PATH: str = os.getenv("MODEL_PATH", "model/rf_model.pkl")
LE_CATEGORY_PATH: str = os.getenv("LE_CATEGORY_PATH", "model/le_category.pkl")
LE_PROTOCOL_PATH: str = os.getenv("LE_PROTOCOL_PATH", "model/le_protocol.pkl")
LE_LABEL_PATH: str = os.getenv("LE_LABEL_PATH", "model/le_label.pkl")
TRAINING_DATA_PATH: str = os.getenv("TRAINING_DATA_PATH", "data/training_data.csv")

# Confidence threshold — below this, HIGH is downgraded to MEDIUM
CONFIDENCE_THRESHOLD: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.70"))

# ─── RISK SCORE LABELS ───────────────────────────────────────────────────────

RISK_LABELS: dict = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}

# Risk scores that should trigger analyst notifications
ALERT_THRESHOLDS: list = ["HIGH", "CRITICAL"]

# ─── NOTIFICATIONS (OPTIONAL) ────────────────────────────────────────────────

SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST: str = os.getenv("SMTP_HOST", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASS: str = os.getenv("SMTP_PASS", "")
ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")

# ─── PRIVATE IP RANGES (SKIP ENRICHMENT) ─────────────────────────────────────

PRIVATE_IP_PREFIXES: tuple = (
    "127.", "0.", "10.", "169.254.",
    "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "::1", "fe80:",
)

# ─── FEATURE COLUMNS (must match training order) ─────────────────────────────

FEATURE_COLUMNS: list = [
    "alert_severity",
    "abuse_confidence_score",
    "vt_malicious_count",
    "alert_category_encoded",
    "dest_port",
    "protocol_encoded",
    "src_ip_frequency",
]

logger.info("Configuration loaded successfully.")
