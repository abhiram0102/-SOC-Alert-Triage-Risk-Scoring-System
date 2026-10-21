"""
generate_training_data.py — Generates realistic synthetic training data
for the SOC ML risk scoring model. Produces a balanced dataset that
mirrors real Suricata alert distributions with proper class representation.

Run: python3 generate_training_data.py
Output: data/training_data.csv
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

random.seed(42)
np.random.seed(42)

# ─── CATEGORY POOLS ──────────────────────────────────────────────────────────

CATEGORIES = [
    "Attempted Information Leak",
    "Information Leak",
    "Attempted Administrator Privilege Gain",
    "Attempted User Privilege Gain",
    "Web Application Attack",
    "Trojan Activity",
    "Denial of Service",
    "Network Scan",
    "Brute Force",
    "Malware Command and Control",
    "Exploit Kit Activity",
    "Misc Activity",
    "A Network Trojan was detected",
    "Potentially Bad Traffic",
    "Not Suspicious Traffic",
    "Unknown Traffic",
]

PROTOCOLS = ["tcp", "udp", "icmp", "dns", "http", "tls"]

HIGH_RISK_PORTS = [22, 23, 25, 445, 3389, 1433, 3306, 4444, 8080, 6379]
COMMON_PORTS = [80, 443, 8080, 8443, 53, 21, 25, 110, 143, 993, 995]
ALL_PORTS = HIGH_RISK_PORTS + COMMON_PORTS + list(range(1024, 65535, 100))


def make_low_alert():
    """Generate a LOW-risk alert: benign traffic, clean IPs."""
    return {
        "alert_severity": random.choice([3, 3, 3, 2]),
        "abuse_confidence_score": random.randint(0, 10),
        "vt_malicious_count": random.choice([0, 0, 0, 1]),
        "alert_category": random.choice([
            "Not Suspicious Traffic", "Unknown Traffic",
            "Misc Activity", "Information Leak",
        ]),
        "dest_port": random.choice(COMMON_PORTS),
        "protocol": random.choice(["tcp", "udp", "http"]),
        "src_ip_frequency": random.randint(1, 5),
        "risk_label": "LOW",
    }


def make_medium_alert():
    """Generate a MEDIUM-risk alert: some indicators, moderate confidence."""
    return {
        "alert_severity": random.choice([2, 2, 3]),
        "abuse_confidence_score": random.randint(10, 40),
        "vt_malicious_count": random.randint(0, 5),
        "alert_category": random.choice([
            "Potentially Bad Traffic", "Attempted Information Leak",
            "Misc Activity", "Network Scan", "Attempted User Privilege Gain",
        ]),
        "dest_port": random.choice(COMMON_PORTS + HIGH_RISK_PORTS),
        "protocol": random.choice(PROTOCOLS),
        "src_ip_frequency": random.randint(3, 20),
        "risk_label": "MEDIUM",
    }


def make_high_alert():
    """Generate a HIGH-risk alert: confirmed malicious indicators."""
    return {
        "alert_severity": random.choice([1, 2]),
        "abuse_confidence_score": random.randint(40, 80),
        "vt_malicious_count": random.randint(5, 25),
        "alert_category": random.choice([
            "Web Application Attack", "Brute Force",
            "Attempted Administrator Privilege Gain",
            "Exploit Kit Activity", "Denial of Service",
        ]),
        "dest_port": random.choice(HIGH_RISK_PORTS),
        "protocol": random.choice(["tcp", "udp"]),
        "src_ip_frequency": random.randint(15, 80),
        "risk_label": "HIGH",
    }


def make_critical_alert():
    """Generate a CRITICAL-risk alert: severe threat with strong TI signals."""
    return {
        "alert_severity": 1,
        "abuse_confidence_score": random.randint(75, 100),
        "vt_malicious_count": random.randint(20, 70),
        "alert_category": random.choice([
            "Trojan Activity", "Malware Command and Control",
            "A Network Trojan was detected",
            "Attempted Administrator Privilege Gain",
        ]),
        "dest_port": random.choice(HIGH_RISK_PORTS),
        "protocol": random.choice(["tcp", "udp"]),
        "src_ip_frequency": random.randint(50, 300),
        "risk_label": "CRITICAL",
    }


def generate_dataset(
    n_low: int = 2000,
    n_medium: int = 1500,
    n_high: int = 1000,
    n_critical: int = 500,
) -> pd.DataFrame:
    """Generate a balanced synthetic dataset for training."""
    records = (
        [make_low_alert() for _ in range(n_low)]
        + [make_medium_alert() for _ in range(n_medium)]
        + [make_high_alert() for _ in range(n_high)]
        + [make_critical_alert() for _ in range(n_critical)]
    )
    df = pd.DataFrame(records)
    # Shuffle to break any ordering artifacts
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Generated {len(df)} training samples:")
    print(df["risk_label"].value_counts())
    print("\nFeature statistics:")
    print(df.describe())
    return df


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    df = generate_dataset()
    out_path = "data/training_data.csv"
    df.to_csv(out_path, index=False)
    print(f"\nTraining data saved to: {out_path}")
