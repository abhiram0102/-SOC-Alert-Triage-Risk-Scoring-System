"""
pipeline.py — Main SOC Alert Triage Orchestration Engine
Continuously polls Elasticsearch for unenriched Suricata alerts,
enriches them with threat intelligence, scores with ML, and updates ES.

Run:  python3 pipeline.py [--once] [--batch-size 50] [--dry-run]
"""

import os
import sys
import time
import json
import hashlib
import logging
import argparse
import smtplib
import threading
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

import requests
from elasticsearch import Elasticsearch, NotFoundError, ConnectionError as ESConnectionError

# ─── PATH SETUP ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "enrichment"))
sys.path.insert(0, str(BASE_DIR / "ml"))

from config.config import (
    ES_HOST, ES_INDEX, ES_USERNAME, ES_PASSWORD, ES_VERIFY_CERTS,
    POLL_INTERVAL, BATCH_SIZE, FREQ_WINDOW_MINUTES,
    ALERT_THRESHOLDS, SLACK_WEBHOOK_URL,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL_TO,
    LOG_FILE,
)
from enrichment.enrichment import enrich_alert
from ml.ml_scorer import score_alert, score_batch, get_model_info

# ─── LOGGING ─────────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, mode="a"),
    ],
)
logger = logging.getLogger("soc_triage.pipeline")

# ─── ELASTICSEARCH CLIENT ─────────────────────────────────────────────────────

def build_es_client() -> Elasticsearch:
    """Build and return an Elasticsearch client with retry configuration."""
    kwargs: Dict[str, Any] = {
        "hosts": [ES_HOST],
        "retry_on_timeout": True,
        "max_retries": 5,
        "request_timeout": 30,
        "verify_certs": ES_VERIFY_CERTS,
    }
    if ES_USERNAME and ES_PASSWORD:
        kwargs["basic_auth"] = (ES_USERNAME, ES_PASSWORD)

    client = Elasticsearch(**kwargs)
    return client


# ─── IP FREQUENCY TRACKER ────────────────────────────────────────────────────

class IPFrequencyTracker:
    """
    Sliding-window frequency counter for source IPs.
    Thread-safe using a lock; uses a deque per IP for O(1) cleanup.
    """

    def __init__(self, window_minutes: int = FREQ_WINDOW_MINUTES):
        self._window = timedelta(minutes=window_minutes)
        self._lock = threading.Lock()
        self._tracker: Dict[str, deque] = defaultdict(deque)

    def record_and_count(self, ip: str) -> int:
        """Record a new occurrence of ip and return the count in the window."""
        now = datetime.now(timezone.utc)
        cutoff = now - self._window
        with self._lock:
            q = self._tracker[ip]
            # Evict old entries from the left
            while q and q[0] < cutoff:
                q.popleft()
            q.append(now)
            return len(q)

    def get_count(self, ip: str) -> int:
        """Return current count for ip without recording a new entry."""
        now = datetime.now(timezone.utc)
        cutoff = now - self._window
        with self._lock:
            q = self._tracker[ip]
            while q and q[0] < cutoff:
                q.popleft()
            return len(q)

    def top_offenders(self, n: int = 10) -> List[Tuple[str, int]]:
        """Return the n IPs with the highest frequency counts."""
        now = datetime.now(timezone.utc)
        cutoff = now - self._window
        with self._lock:
            counts = []
            for ip, q in self._tracker.items():
                while q and q[0] < cutoff:
                    q.popleft()
                if q:
                    counts.append((ip, len(q)))
            return sorted(counts, key=lambda x: -x[1])[:n]


# ─── DEDUPLICATION CACHE ─────────────────────────────────────────────────────

class AlertDeduplicator:
    """
    In-memory deduplication cache. Generates a fingerprint from
    (src_ip, dest_ip, alert_sid, dest_port) to detect repeated alerts.
    Expired fingerprints are evicted after TTL.
    """

    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._seen: Dict[str, float] = {}

    def _fingerprint(self, alert: Dict[str, Any]) -> str:
        key = ":".join([
            str(alert.get("src_ip", "")),
            str(alert.get("dest_ip", "")),
            str(alert.get("alert_sid", "")),
            str(alert.get("dest_port", "")),
        ])
        return hashlib.md5(key.encode()).hexdigest()

    def is_duplicate(self, alert: Dict[str, Any]) -> bool:
        """Returns True if this alert was seen within TTL."""
        fp = self._fingerprint(alert)
        now = time.time()
        with self._lock:
            # Evict expired entries
            expired = [k for k, ts in self._seen.items() if now - ts > self._ttl]
            for k in expired:
                del self._seen[k]

            if fp in self._seen:
                return True
            self._seen[fp] = now
            return False

    @property
    def cache_size(self) -> int:
        return len(self._seen)


# ─── NOTIFICATION FUNCTIONS ──────────────────────────────────────────────────

def send_slack_notification(alert: Dict[str, Any], risk_label: str, confidence: float) -> None:
    """Post a critical alert notification to a Slack webhook."""
    if not SLACK_WEBHOOK_URL:
        return
    enrich = alert.get("enrichment", {})
    mitre = alert.get("mitre", {})
    payload = {
        "text": f":rotating_light: *{risk_label} ALERT* — {alert.get('alert_signature', 'Unknown Signature')}",
        "attachments": [
            {
                "color": "#FF0000" if risk_label == "CRITICAL" else "#FFA500",
                "fields": [
                    {"title": "Source IP",    "value": alert.get("src_ip", "N/A"),     "short": True},
                    {"title": "Dest IP",      "value": alert.get("dest_ip", "N/A"),    "short": True},
                    {"title": "Protocol",     "value": alert.get("proto", "N/A"),      "short": True},
                    {"title": "Dest Port",    "value": str(alert.get("dest_port", "")), "short": True},
                    {"title": "Abuse Score",  "value": str(enrich.get("abuse_confidence_score", 0)), "short": True},
                    {"title": "VT Malicious", "value": str(enrich.get("vt_malicious_count", 0)), "short": True},
                    {"title": "IP Freq",      "value": str(alert.get("src_ip_frequency", "")), "short": True},
                    {"title": "Confidence",   "value": f"{confidence:.0%}", "short": True},
                    {"title": "MITRE",        "value": f"{mitre.get('technique_id', '')} — {mitre.get('technique_name', '')}", "short": False},
                ],
                "footer": "SOC Triage System",
                "ts": int(time.time()),
            }
        ],
    }
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        resp.raise_for_status()
        logger.debug("Slack notification sent for %s alert", risk_label)
    except Exception as exc:
        logger.warning("Slack notification failed: %s", exc)


def send_email_notification(alert: Dict[str, Any], risk_label: str) -> None:
    """Send email notification for critical alerts."""
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, ALERT_EMAIL_TO]):
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SOC ALERT] {risk_label}: {alert.get('alert_signature', 'Unknown')}"
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL_TO

        body = f"""
        <h2 style="color:red">{risk_label} Alert Detected</h2>
        <table>
        <tr><td><b>Signature</b></td><td>{alert.get('alert_signature','')}</td></tr>
        <tr><td><b>Source IP</b></td><td>{alert.get('src_ip','')}</td></tr>
        <tr><td><b>Dest IP</b></td><td>{alert.get('dest_ip','')}</td></tr>
        <tr><td><b>Dest Port</b></td><td>{alert.get('dest_port','')}</td></tr>
        <tr><td><b>Protocol</b></td><td>{alert.get('proto','')}</td></tr>
        <tr><td><b>Category</b></td><td>{alert.get('alert_category','')}</td></tr>
        <tr><td><b>Abuse Score</b></td><td>{alert.get('enrichment',{}).get('abuse_confidence_score',0)}</td></tr>
        <tr><td><b>VT Malicious</b></td><td>{alert.get('enrichment',{}).get('vt_malicious_count',0)}</td></tr>
        <tr><td><b>MITRE</b></td><td>{alert.get('mitre',{}).get('technique_id','')} — {alert.get('mitre',{}).get('technique_name','')}</td></tr>
        </table>
        <p>Timestamp: {datetime.now(timezone.utc).isoformat()}</p>
        """
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())
        logger.debug("Email notification sent for %s alert", risk_label)
    except Exception as exc:
        logger.warning("Email notification failed: %s", exc)


# ─── ELASTICSEARCH OPERATIONS ────────────────────────────────────────────────

def fetch_unenriched_alerts(es: Elasticsearch, batch_size: int = BATCH_SIZE) -> List[Dict]:
    """
    Query Elasticsearch for alerts where enriched='false'.
    Returns up to batch_size documents sorted newest first.
    """
    query = {
        "query": {
            "bool": {
                "must": [{"term": {"enriched": "false"}}],
                "filter": [
                    {"term": {"event_type": "alert"}}
                ],
            }
        },
        "size": batch_size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": True,
    }
    try:
        result = es.search(index=ES_INDEX, body=query)
        hits = result.get("hits", {}).get("hits", [])
        logger.debug("Fetched %d unenriched alerts from ES", len(hits))
        return hits
    except ESConnectionError as exc:
        logger.error("Elasticsearch connection error: %s", exc)
        return []
    except Exception as exc:
        logger.error("Elasticsearch query error: %s", exc, exc_info=True)
        return []


def update_alert_document(
    es: Elasticsearch,
    doc_id: str,
    index: str,
    update_body: Dict[str, Any],
    dry_run: bool = False,
) -> bool:
    """
    Perform a partial update on an Elasticsearch document.
    Returns True on success, False on failure.
    """
    if dry_run:
        logger.info("[DRY RUN] Would update %s/%s: %s", index, doc_id,
                    {k: v for k, v in update_body.items() if k != "enrichment"})
        return True
    try:
        es.update(
            index=index,
            id=doc_id,
            body={"doc": update_body, "doc_as_upsert": False},
            retry_on_conflict=3,
        )
        return True
    except NotFoundError:
        logger.warning("Document %s not found in %s (already deleted?)", doc_id, index)
        return False
    except Exception as exc:
        logger.error("Failed to update ES document %s: %s", doc_id, exc)
        return False


def count_unenriched(es: Elasticsearch) -> int:
    """Return count of unenriched alerts remaining in Elasticsearch."""
    try:
        result = es.count(
            index=ES_INDEX,
            body={"query": {"term": {"enriched": "false"}}},
        )
        return result.get("count", 0)
    except Exception:
        return -1


# ─── MAIN PIPELINE ───────────────────────────────────────────────────────────

class SOCPipeline:
    """
    Main triage pipeline orchestrator.
    Manages the poll → enrich → score → update → notify cycle.
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.es = build_es_client()
        self.freq_tracker = IPFrequencyTracker()
        self.deduplicator = AlertDeduplicator(ttl_seconds=300)

        # Counters for health reporting
        self.stats = {
            "total_processed": 0,
            "total_high_critical": 0,
            "total_errors": 0,
            "cycles": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

    def _check_es_connection(self) -> bool:
        """Verify Elasticsearch is reachable."""
        try:
            health = self.es.cluster.health(request_timeout=5)
            status = health.get("status", "red")
            if status == "red":
                logger.error("Elasticsearch cluster health is RED")
                return False
            logger.debug("ES cluster health: %s", status)
            return True
        except Exception as exc:
            logger.error("Cannot reach Elasticsearch at %s: %s", ES_HOST, exc)
            return False

    def _process_single_alert(
        self,
        hit: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Process one alert through the full enrichment + scoring pipeline.
        Returns the update payload, or None if the alert should be skipped.
        """
        alert: Dict[str, Any] = hit["_source"]
        doc_id: str = hit["_id"]
        index: str = hit["_index"]

        src_ip = alert.get("src_ip", "0.0.0.0")

        # ── Deduplication ─────────────────────────────────────────────
        if self.deduplicator.is_duplicate(alert):
            logger.debug("Duplicate alert skipped: %s from %s", alert.get("alert_signature"), src_ip)
            # Still mark as enriched to prevent re-processing
            update_alert_document(self.es, doc_id, index, {
                "enriched": "true",
                "risk_score": "DUPLICATE",
                "triage_timestamp": datetime.now(timezone.utc).isoformat(),
            }, self.dry_run)
            return None

        # ── IP Frequency ──────────────────────────────────────────────
        freq = self.freq_tracker.record_and_count(src_ip)
        alert["src_ip_frequency"] = freq

        # ── Threat Intelligence Enrichment ────────────────────────────
        try:
            alert = enrich_alert(alert)
        except Exception as exc:
            logger.error("Enrichment failed for alert %s: %s", doc_id, exc)
            alert["enrichment"] = {
                "abuse_confidence_score": 0,
                "vt_malicious_count": 0,
                "enriched_at": datetime.now(timezone.utc).isoformat(),
                "enrichment_error": str(exc),
            }

        # ── ML Scoring ────────────────────────────────────────────────
        try:
            risk_label, confidence = score_alert(alert)
        except Exception as exc:
            logger.error("ML scoring failed for alert %s: %s", doc_id, exc)
            risk_label, confidence = "MEDIUM", 0.5
            self.stats["total_errors"] += 1

        # ── Build update payload ──────────────────────────────────────
        update_data: Dict[str, Any] = {
            "enriched": "true",
            "risk_score": risk_label,
            "ml_confidence": confidence,
            "src_ip_frequency": freq,
            "enrichment": alert.get("enrichment", {}),
            "mitre": alert.get("mitre", {}),
            "triage_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # ── Write to Elasticsearch ────────────────────────────────────
        success = update_alert_document(self.es, doc_id, index, update_data, self.dry_run)

        # ── Statistics ───────────────────────────────────────────────
        self.stats["total_processed"] += 1
        if risk_label in ALERT_THRESHOLDS:
            self.stats["total_high_critical"] += 1

        # ── Console output for HIGH / CRITICAL ────────────────────────
        if risk_label in ALERT_THRESHOLDS:
            enrich = alert.get("enrichment", {})
            mitre = alert.get("mitre", {})
            print(
                f"\n{'🚨' if risk_label == 'CRITICAL' else '⚠️ '} [{risk_label}] "
                f"{alert.get('alert_signature', 'Unknown')} | "
                f"src={src_ip} | "
                f"dst={alert.get('dest_ip', '?')}:{alert.get('dest_port', '?')} | "
                f"abuse={enrich.get('abuse_confidence_score', 0)} | "
                f"vt={enrich.get('vt_malicious_count', 0)} | "
                f"freq={freq} | conf={confidence:.0%} | "
                f"MITRE={mitre.get('technique_id', '?')}"
            )

            # ── Notifications ─────────────────────────────────────────
            send_slack_notification(alert, risk_label, confidence)
            if risk_label == "CRITICAL":
                send_email_notification(alert, risk_label)

        return update_data

    def run_cycle(self) -> int:
        """
        Execute one polling cycle: fetch → process → return count processed.
        """
        self.stats["cycles"] += 1
        cycle_start = time.monotonic()

        hits = fetch_unenriched_alerts(self.es, BATCH_SIZE)
        if not hits:
            return 0

        logger.info("Cycle %d: processing %d alerts...", self.stats["cycles"], len(hits))

        processed = 0
        for hit in hits:
            try:
                result = self._process_single_alert(hit)
                if result is not None:
                    processed += 1
            except Exception as exc:
                logger.error("Unhandled error in alert processing: %s", exc, exc_info=True)
                self.stats["total_errors"] += 1

        elapsed = time.monotonic() - cycle_start
        throughput = processed / elapsed if elapsed > 0 else 0
        logger.info(
            "Cycle %d complete: %d processed in %.2fs (%.1f alerts/sec)",
            self.stats["cycles"], processed, elapsed, throughput,
        )
        return processed

    def print_status(self) -> None:
        """Print pipeline health summary to stdout."""
        remaining = count_unenriched(self.es)
        top = self.freq_tracker.top_offenders(5)
        print("\n" + "─" * 60)
        print(f"  SOC Triage Pipeline — Status Report")
        print("─" * 60)
        print(f"  Started:          {self.stats['started_at']}")
        print(f"  Cycles:           {self.stats['cycles']}")
        print(f"  Total Processed:  {self.stats['total_processed']}")
        print(f"  HIGH/CRITICAL:    {self.stats['total_high_critical']}")
        print(f"  Errors:           {self.stats['total_errors']}")
        print(f"  ES Remaining:     {remaining}")
        print(f"  Dedup Cache:      {self.deduplicator.cache_size} entries")
        if top:
            print(f"  Top Offenders:    {', '.join(f'{ip}({n})' for ip, n in top)}")
        print("─" * 60 + "\n")

    def run(self, run_once: bool = False) -> None:
        """
        Main loop. Polls Elasticsearch every POLL_INTERVAL seconds.
        Set run_once=True for single-pass mode (useful for testing).
        """
        # Verify connections
        logger.info("Starting SOC Triage Pipeline")
        logger.info("Elasticsearch: %s | Index: %s", ES_HOST, ES_INDEX)

        if not self._check_es_connection():
            logger.error("Cannot connect to Elasticsearch. Exiting.")
            sys.exit(1)

        # Log model info
        try:
            info = get_model_info()
            logger.info(
                "ML Model: %s | Features: %d | Classes: %s",
                info["model_type"],
                len(info["features"]),
                info["classes"],
            )
        except Exception as exc:
            logger.error("Failed to load ML model: %s", exc)
            logger.error("Run train_model.py first to generate model artefacts.")
            sys.exit(1)

        if self.dry_run:
            logger.warning("DRY RUN mode — Elasticsearch will not be updated.")

        logger.info("Polling every %ds | Batch size: %d", POLL_INTERVAL, BATCH_SIZE)

        cycle = 0
        while True:
            try:
                processed = self.run_cycle()
                cycle += 1

                # Print status every 10 cycles
                if cycle % 10 == 0:
                    self.print_status()

                if run_once:
                    logger.info("Run-once mode: pipeline complete.")
                    self.print_status()
                    break

                if processed < BATCH_SIZE:
                    # Fewer alerts than batch size = caught up; sleep full interval
                    logger.debug("Caught up with alerts. Sleeping %ds...", POLL_INTERVAL)
                    time.sleep(POLL_INTERVAL)
                else:
                    # More alerts likely waiting; minimal sleep to keep up
                    time.sleep(1)

            except KeyboardInterrupt:
                logger.info("Shutdown signal received. Exiting cleanly.")
                self.print_status()
                break
            except Exception as exc:
                logger.error("Unexpected pipeline error: %s", exc, exc_info=True)
                self.stats["total_errors"] += 1
                time.sleep(5)  # Brief pause before retry


# ─── CLI ENTRYPOINT ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Alert Triage Pipeline")
    parser.add_argument(
        "--once", action="store_true",
        help="Process one batch and exit (useful for cron / testing)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=BATCH_SIZE,
        help=f"Alerts per batch (default: {BATCH_SIZE})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Enrich and score alerts but do NOT write back to Elasticsearch",
    )
    args = parser.parse_args()

    if args.batch_size != BATCH_SIZE:
        import config.config as cfg
        cfg.BATCH_SIZE = args.batch_size

    pipeline = SOCPipeline(dry_run=args.dry_run)
    pipeline.run(run_once=args.once)
