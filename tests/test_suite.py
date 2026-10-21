"""
tests/test_suite.py — Comprehensive unit tests for the SOC Triage System
Tests all major components: enrichment, ML scoring, pipeline logic.

Run: pytest tests/ -v --tb=short
Run with coverage: pytest tests/ -v --cov=. --cov-report=term-missing
"""

import os
import sys
import json
import time
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path
from datetime import datetime, timezone

# ─── PATH SETUP ───────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "enrichment"))
sys.path.insert(0, str(BASE_DIR / "ml"))
sys.path.insert(0, str(BASE_DIR / "pipeline"))

os.environ.setdefault("ABUSEIPDB_API_KEY", "test_abuse_key")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "test_vt_key")
os.environ.setdefault("ELASTICSEARCH_HOST", "http://localhost:9200")
os.environ.setdefault("ELASTICSEARCH_INDEX", "suricata-alerts-*")
os.environ.setdefault("USE_REDIS", "false")
os.environ.setdefault("LOG_FILE", "logs/test.log")
os.makedirs("logs", exist_ok=True)

# ─── SAMPLE ALERT FIXTURES ───────────────────────────────────────────────────

SAMPLE_ALERT_HIGH = {
    "src_ip": "45.33.32.156",
    "dest_ip": "192.168.1.100",
    "src_port": 54321,
    "dest_port": 22,
    "proto": "tcp",
    "alert_signature": "ET SCAN Potential SSH Brute Force Attack",
    "alert_category": "Brute Force",
    "alert_severity": 1,
    "alert_sid": 2001219,
    "@timestamp": "2025-01-15T10:30:00Z",
    "src_ip_frequency": 45,
}

SAMPLE_ALERT_LOW = {
    "src_ip": "192.168.1.50",
    "dest_ip": "192.168.1.1",
    "src_port": 12345,
    "dest_port": 80,
    "proto": "tcp",
    "alert_signature": "ET POLICY HTTP Request to .exe File",
    "alert_category": "Not Suspicious Traffic",
    "alert_severity": 3,
    "alert_sid": 2000001,
    "@timestamp": "2025-01-15T10:31:00Z",
    "src_ip_frequency": 2,
}

SAMPLE_ALERT_CRITICAL = {
    "src_ip": "198.51.100.1",
    "dest_ip": "192.168.1.10",
    "src_port": 6789,
    "dest_port": 4444,
    "proto": "tcp",
    "alert_signature": "ET MALWARE Meterpreter Reverse Shell",
    "alert_category": "Trojan Activity",
    "alert_severity": 1,
    "alert_sid": 2019714,
    "@timestamp": "2025-01-15T10:32:00Z",
    "src_ip_frequency": 180,
}


# ─── TEST: MITRE ATT&CK MAPPING ──────────────────────────────────────────────

class TestMitreMapping(unittest.TestCase):

    def setUp(self):
        from enrichment.enrichment import map_mitre_attack
        self.map_fn = map_mitre_attack

    def test_known_category_exact_match(self):
        result = self.map_fn("Brute Force")
        self.assertEqual(result["tactic"], "Credential Access")
        self.assertEqual(result["technique_id"], "T1110")
        self.assertIn("Brute", result["technique_name"])

    def test_known_category_web_attack(self):
        result = self.map_fn("Web Application Attack")
        self.assertEqual(result["tactic"], "Initial Access")
        self.assertEqual(result["technique_id"], "T1190")

    def test_unknown_category_fallback(self):
        result = self.map_fn("Some Completely Unknown Category XYZ")
        self.assertEqual(result["technique_id"], "T0000")
        self.assertEqual(result["tactic"], "Unknown")

    def test_trojan_activity(self):
        result = self.map_fn("Trojan Activity")
        self.assertEqual(result["tactic"], "Command and Control")

    def test_network_scan(self):
        result = self.map_fn("Network Scan")
        self.assertEqual(result["tactic"], "Reconnaissance")
        self.assertEqual(result["technique_id"], "T1595")

    def test_dos_category(self):
        result = self.map_fn("Denial of Service")
        self.assertEqual(result["tactic"], "Impact")


# ─── TEST: IP DETECTION ──────────────────────────────────────────────────────

class TestIPDetection(unittest.TestCase):

    def setUp(self):
        from enrichment.enrichment import is_private_ip
        self.is_private = is_private_ip

    def test_loopback(self):
        self.assertTrue(self.is_private("127.0.0.1"))

    def test_rfc1918_10(self):
        self.assertTrue(self.is_private("10.0.0.1"))

    def test_rfc1918_192(self):
        self.assertTrue(self.is_private("192.168.1.1"))

    def test_rfc1918_172(self):
        self.assertTrue(self.is_private("172.16.0.1"))

    def test_public_ip(self):
        self.assertFalse(self.is_private("8.8.8.8"))

    def test_public_ip_2(self):
        self.assertFalse(self.is_private("45.33.32.156"))


# ─── TEST: ABUSEIPDB ENRICHMENT ──────────────────────────────────────────────

class TestAbuseIPDB(unittest.TestCase):

    def setUp(self):
        from enrichment import enrichment as enr
        enr._memory_cache.clear()

    @patch("enrichment.enrichment._session")
    def test_successful_lookup(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 42,
                "countryCode": "RU",
                "isp": "DigitalOcean",
                "usageType": "Data Center/Web Hosting",
                "domain": "digitalocean.com",
                "isTor": False,
            }
        }
        mock_resp.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_resp

        from enrichment.enrichment import query_abuseipdb
        result = query_abuseipdb("45.33.32.156")

        self.assertEqual(result["abuse_confidence_score"], 85)
        self.assertEqual(result["country_code"], "RU")
        self.assertEqual(result["total_reports"], 42)
        self.assertFalse(result["is_tor"])

    def test_private_ip_skipped(self):
        from enrichment.enrichment import query_abuseipdb
        result = query_abuseipdb("192.168.1.1")
        self.assertEqual(result["abuse_confidence_score"], 0)

    @patch("enrichment.enrichment._session")
    def test_api_timeout_returns_zeros(self, mock_session):
        import requests as req
        mock_session.get.side_effect = req.exceptions.Timeout
        from enrichment.enrichment import query_abuseipdb
        result = query_abuseipdb("45.33.32.156")
        self.assertEqual(result["abuse_confidence_score"], 0)

    @patch("enrichment.enrichment._session")
    def test_cache_hit(self, mock_session):
        from enrichment.enrichment import query_abuseipdb, _memory_cache, CACHE_TTL
        _memory_cache["abuseipdb:1.2.3.4"] = ({"abuse_confidence_score": 50, "total_reports": 5,
            "country_code": "US", "isp": "AWS", "usage_type": "Data Center",
            "domain": "aws.com", "is_tor": False}, time.time())
        result = query_abuseipdb("1.2.3.4")
        self.assertEqual(result["abuse_confidence_score"], 50)
        mock_session.get.assert_not_called()


# ─── TEST: ENRICH ALERT ──────────────────────────────────────────────────────

class TestEnrichAlert(unittest.TestCase):

    def setUp(self):
        from enrichment import enrichment as enr
        enr._memory_cache.clear()

    @patch("enrichment.enrichment.query_virustotal_ip")
    @patch("enrichment.enrichment.query_abuseipdb")
    def test_full_enrichment_structure(self, mock_abuse, mock_vt):
        mock_abuse.return_value = {
            "abuse_confidence_score": 75,
            "total_reports": 10,
            "country_code": "CN",
            "isp": "Alibaba",
            "usage_type": "Data Center",
            "domain": "alibaba.com",
            "is_tor": False,
        }
        mock_vt.return_value = {
            "vt_malicious_count": 15,
            "vt_suspicious_count": 2,
            "vt_harmless_count": 40,
            "vt_reputation": -50,
        }
        from enrichment.enrichment import enrich_alert
        import copy
        alert = copy.deepcopy(SAMPLE_ALERT_HIGH)
        result = enrich_alert(alert)

        self.assertIn("enrichment", result)
        self.assertIn("mitre", result)
        self.assertEqual(result["enrichment"]["abuse_confidence_score"], 75)
        self.assertEqual(result["enrichment"]["vt_malicious_count"], 15)
        self.assertEqual(result["enrichment"]["src_country_code"], "CN")
        self.assertIn("enriched_at", result["enrichment"])
        self.assertEqual(result["mitre"]["technique_id"], "T1110")  # Brute Force


# ─── TEST: IP FREQUENCY TRACKER ──────────────────────────────────────────────

class TestIPFrequencyTracker(unittest.TestCase):

    def setUp(self):
        from pipeline.pipeline import IPFrequencyTracker
        self.tracker = IPFrequencyTracker(window_minutes=60)

    def test_first_occurrence(self):
        count = self.tracker.record_and_count("10.0.0.1")
        self.assertEqual(count, 1)

    def test_multiple_occurrences(self):
        for _ in range(10):
            self.tracker.record_and_count("10.0.0.2")
        count = self.tracker.record_and_count("10.0.0.2")
        self.assertEqual(count, 11)

    def test_different_ips_independent(self):
        self.tracker.record_and_count("1.1.1.1")
        self.tracker.record_and_count("1.1.1.1")
        count = self.tracker.record_and_count("2.2.2.2")
        self.assertEqual(count, 1)

    def test_top_offenders(self):
        for _ in range(5):
            self.tracker.record_and_count("5.5.5.5")
        for _ in range(10):
            self.tracker.record_and_count("6.6.6.6")
        self.tracker.record_and_count("7.7.7.7")
        top = self.tracker.top_offenders(n=3)
        self.assertEqual(top[0][0], "6.6.6.6")
        self.assertEqual(top[0][1], 10)


# ─── TEST: DEDUPLICATOR ──────────────────────────────────────────────────────

class TestAlertDeduplicator(unittest.TestCase):

    def setUp(self):
        from pipeline.pipeline import AlertDeduplicator
        self.dedup = AlertDeduplicator(ttl_seconds=300)

    def test_first_alert_not_duplicate(self):
        self.assertFalse(self.dedup.is_duplicate(SAMPLE_ALERT_HIGH))

    def test_same_alert_is_duplicate(self):
        self.dedup.is_duplicate(SAMPLE_ALERT_HIGH)
        self.assertTrue(self.dedup.is_duplicate(SAMPLE_ALERT_HIGH))

    def test_different_src_ip_not_duplicate(self):
        import copy
        a1 = copy.deepcopy(SAMPLE_ALERT_HIGH)
        a2 = copy.deepcopy(SAMPLE_ALERT_HIGH)
        a2["src_ip"] = "9.9.9.9"
        self.dedup.is_duplicate(a1)
        self.assertFalse(self.dedup.is_duplicate(a2))

    def test_different_port_not_duplicate(self):
        import copy
        a1 = copy.deepcopy(SAMPLE_ALERT_HIGH)
        a2 = copy.deepcopy(SAMPLE_ALERT_HIGH)
        a2["dest_port"] = 443
        self.dedup.is_duplicate(a1)
        self.assertFalse(self.dedup.is_duplicate(a2))


# ─── TEST: ML RULE-BASED OVERRIDES ───────────────────────────────────────────

class TestRuleBasedOverrides(unittest.TestCase):

    def setUp(self):
        from ml.ml_scorer import _rule_based_override
        self.override = _rule_based_override

    def test_perfect_abuse_score_and_high_vt(self):
        alert = {
            "enrichment": {
                "abuse_confidence_score": 100,
                "vt_malicious_count": 15,
                "is_tor_exit": False,
            }
        }
        self.assertEqual(self.override(alert), "CRITICAL")

    def test_tor_exit_with_vt_hits(self):
        alert = {
            "enrichment": {
                "abuse_confidence_score": 30,
                "vt_malicious_count": 8,
                "is_tor_exit": True,
            }
        }
        self.assertEqual(self.override(alert), "HIGH")

    def test_clean_ip_no_override(self):
        alert = {
            "enrichment": {
                "abuse_confidence_score": 0,
                "vt_malicious_count": 0,
                "is_tor_exit": False,
            },
            "alert_severity": 3,
        }
        self.assertIsNone(self.override(alert))

    def test_high_abuse_not_100_no_forced_critical(self):
        alert = {
            "enrichment": {
                "abuse_confidence_score": 95,
                "vt_malicious_count": 5,
                "is_tor_exit": False,
            }
        }
        # 95 != 100, should not force CRITICAL
        result = self.override(alert)
        self.assertNotEqual(result, "CRITICAL")


# ─── TEST: CACHE STATS ───────────────────────────────────────────────────────

class TestCacheStats(unittest.TestCase):

    def setUp(self):
        from enrichment import enrichment as enr
        enr._memory_cache.clear()

    def test_empty_cache(self):
        from enrichment.enrichment import get_cache_stats
        stats = get_cache_stats()
        self.assertEqual(stats["total_entries"], 0)
        self.assertEqual(stats["active_entries"], 0)

    def test_populated_cache(self):
        from enrichment.enrichment import get_cache_stats, _memory_cache
        _memory_cache["test:1.2.3.4"] = ({"score": 50}, time.time())
        _memory_cache["test:5.6.7.8"] = ({"score": 75}, time.time())
        stats = get_cache_stats()
        self.assertEqual(stats["total_entries"], 2)
        self.assertEqual(stats["active_entries"], 2)


# ─── INTEGRATION: Full enrichment cycle (mocked APIs) ───────────────────────

class TestIntegrationEnrichAndScore(unittest.TestCase):
    """End-to-end test: enrich → score pipeline with mocked external calls."""

    @patch("enrichment.enrichment.query_virustotal_ip")
    @patch("enrichment.enrichment.query_abuseipdb")
    def test_high_risk_alert_pipeline(self, mock_abuse, mock_vt):
        mock_abuse.return_value = {
            "abuse_confidence_score": 80, "total_reports": 25,
            "country_code": "CN", "isp": "Acme Hosting",
            "usage_type": "Data Center", "domain": "acme.cn", "is_tor": False,
        }
        mock_vt.return_value = {
            "vt_malicious_count": 20, "vt_suspicious_count": 3,
            "vt_harmless_count": 30, "vt_reputation": -60,
        }

        # Skip model loading for integration test — patch score_alert
        with patch("ml.ml_scorer.score_alert", return_value=("HIGH", 0.85)):
            from enrichment.enrichment import enrich_alert
            from ml.ml_scorer import score_alert
            import copy

            alert = copy.deepcopy(SAMPLE_ALERT_HIGH)
            alert["src_ip_frequency"] = 45
            enriched = enrich_alert(alert)
            label, confidence = score_alert(enriched)

            self.assertEqual(label, "HIGH")
            self.assertEqual(confidence, 0.85)
            self.assertEqual(enriched["enrichment"]["abuse_confidence_score"], 80)
            self.assertEqual(enriched["mitre"]["technique_id"], "T1110")


# ─── RUNNER ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
