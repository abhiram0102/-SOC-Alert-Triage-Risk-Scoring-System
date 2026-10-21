"""
enrichment.py — Threat Intelligence Enrichment Engine
Integrates AbuseIPDB, VirusTotal, GeoIP, and MITRE ATT&CK mapping.
Includes in-memory + optional Redis caching, retry logic, and rate limiting.
"""

import time
import logging
import functools
import ipaddress
import json
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Import config from parent directory if running standalone
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import (
    ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, CACHE_TTL,
    ABUSEIPDB_RATE_LIMIT_DELAY, VIRUSTOTAL_RATE_LIMIT_DELAY,
    API_MAX_RETRIES, API_RETRY_BACKOFF, PRIVATE_IP_PREFIXES,
    USE_REDIS, REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD,
)

logger = logging.getLogger("soc_triage.enrichment")

# ─── MITRE ATT&CK MAPPING ────────────────────────────────────────────────────

MITRE_ATTACK_MAPPING: Dict[str, Dict[str, str]] = {
    "Attempted Information Leak": {
        "tactic": "Discovery", "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
    },
    "Information Leak": {
        "tactic": "Discovery", "technique_id": "T1040",
        "technique_name": "Network Sniffing",
    },
    "Attempted Administrator Privilege Gain": {
        "tactic": "Privilege Escalation", "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
    },
    "Attempted User Privilege Gain": {
        "tactic": "Privilege Escalation", "technique_id": "T1055",
        "technique_name": "Process Injection",
    },
    "Web Application Attack": {
        "tactic": "Initial Access", "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    "Trojan Activity": {
        "tactic": "Command and Control", "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    "Denial of Service": {
        "tactic": "Impact", "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
    },
    "Potential Corporate Privacy Violation": {
        "tactic": "Exfiltration", "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
    },
    "Network Scan": {
        "tactic": "Reconnaissance", "technique_id": "T1595",
        "technique_name": "Active Scanning",
    },
    "Brute Force": {
        "tactic": "Credential Access", "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "Malware Command and Control": {
        "tactic": "Command and Control", "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (C2)",
    },
    "Exploit Kit Activity": {
        "tactic": "Execution", "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
    },
    "Misc Activity": {
        "tactic": "Defense Evasion", "technique_id": "T1070",
        "technique_name": "Indicator Removal",
    },
    "A Network Trojan was detected": {
        "tactic": "Command and Control", "technique_id": "T1219",
        "technique_name": "Remote Access Software",
    },
    "Potentially Bad Traffic": {
        "tactic": "Command and Control", "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    "Not Suspicious Traffic": {
        "tactic": "Unknown", "technique_id": "T0000",
        "technique_name": "No Known Technique",
    },
    "Unknown Traffic": {
        "tactic": "Unknown", "technique_id": "T0000",
        "technique_name": "No Known Technique",
    },
}

_MITRE_FALLBACK: Dict[str, str] = {
    "tactic": "Unknown",
    "technique_id": "T0000",
    "technique_name": "Unmapped Technique",
}

# ─── REQUESTS SESSION WITH RETRY ─────────────────────────────────────────────

def _build_session(max_retries: int = API_MAX_RETRIES) -> requests.Session:
    """Build a requests Session with automatic retry and backoff."""
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=API_RETRY_BACKOFF,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

_session = _build_session()

# ─── CACHE LAYER ─────────────────────────────────────────────────────────────

# In-memory cache: { key: (value, timestamp) }
_memory_cache: Dict[str, Tuple[Any, float]] = {}

# Optional Redis client
_redis_client = None
if USE_REDIS:
    try:
        import redis
        _redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD or None,
            decode_responses=True,
            socket_connect_timeout=2,
        )
        _redis_client.ping()
        logger.info("Redis cache connected at %s:%s", REDIS_HOST, REDIS_PORT)
    except Exception as exc:
        logger.warning("Redis unavailable, falling back to in-memory cache: %s", exc)
        _redis_client = None


def _cache_get(key: str) -> Optional[Any]:
    """Read from Redis or in-memory cache. Returns None on miss."""
    if _redis_client:
        try:
            raw = _redis_client.get(key)
            if raw:
                return json.loads(raw)
        except Exception as exc:
            logger.debug("Redis get failed: %s", exc)

    entry = _memory_cache.get(key)
    if entry:
        value, cached_at = entry
        if time.time() - cached_at < CACHE_TTL:
            return value
        del _memory_cache[key]
    return None


def _cache_set(key: str, value: Any) -> None:
    """Write to Redis or in-memory cache."""
    if _redis_client:
        try:
            _redis_client.setex(key, CACHE_TTL, json.dumps(value))
            return
        except Exception as exc:
            logger.debug("Redis set failed: %s", exc)

    _memory_cache[key] = (value, time.time())

# ─── IP UTILITY ──────────────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    """Return True if the IP is private/reserved and should not be looked up."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False

# ─── ABUSEIPDB ───────────────────────────────────────────────────────────────

def query_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB v2 API for IP reputation.
    Returns a dict with abuse_confidence_score, total_reports, country_code, isp.
    Results are cached for CACHE_TTL seconds.
    """
    empty_result = {
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "country_code": "UNKNOWN",
        "isp": "UNKNOWN",
        "usage_type": "UNKNOWN",
        "domain": "UNKNOWN",
        "is_tor": False,
    }

    if not ABUSEIPDB_API_KEY:
        return empty_result

    if is_private_ip(ip):
        return empty_result

    cache_key = f"abuseipdb:{ip}"
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug("AbuseIPDB cache hit for %s", ip)
        return cached

    time.sleep(ABUSEIPDB_RATE_LIMIT_DELAY)  # rate limit guard

    try:
        resp = _session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        result = {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", "UNKNOWN"),
            "isp": data.get("isp", "UNKNOWN"),
            "usage_type": data.get("usageType", "UNKNOWN"),
            "domain": data.get("domain", "UNKNOWN"),
            "is_tor": data.get("isTor", False),
        }
        _cache_set(cache_key, result)
        logger.debug("AbuseIPDB score for %s: %d", ip, result["abuse_confidence_score"])
        return result
    except requests.exceptions.Timeout:
        logger.warning("AbuseIPDB timeout for %s", ip)
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 422:
            logger.debug("AbuseIPDB: invalid IP format for %s", ip)
        else:
            logger.error("AbuseIPDB HTTP error for %s: %s", ip, exc)
    except Exception as exc:
        logger.error("AbuseIPDB unexpected error for %s: %s", ip, exc)

    return empty_result

# ─── VIRUSTOTAL ───────────────────────────────────────────────────────────────

def query_virustotal_ip(ip: str) -> Dict[str, Any]:
    """
    Query VirusTotal v3 API for an IP address.
    Returns malicious count, suspicious count, and reputation score.
    Respects free-tier rate limit (4 requests/minute).
    """
    empty_result = {
        "vt_malicious_count": 0,
        "vt_suspicious_count": 0,
        "vt_harmless_count": 0,
        "vt_reputation": 0,
    }

    if not VIRUSTOTAL_API_KEY:
        return empty_result

    if is_private_ip(ip):
        return empty_result

    cache_key = f"virustotal:ip:{ip}"
    cached = _cache_get(cache_key)
    if cached is not None:
        logger.debug("VirusTotal cache hit for %s", ip)
        return cached

    time.sleep(VIRUSTOTAL_RATE_LIMIT_DELAY)  # 15s = ~4/min on free tier

    try:
        resp = _session.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        if resp.status_code == 404:
            _cache_set(cache_key, empty_result)
            return empty_result
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "vt_malicious_count": stats.get("malicious", 0),
            "vt_suspicious_count": stats.get("suspicious", 0),
            "vt_harmless_count": stats.get("harmless", 0),
            "vt_reputation": attrs.get("reputation", 0),
        }
        _cache_set(cache_key, result)
        logger.debug("VirusTotal malicious count for %s: %d", ip, result["vt_malicious_count"])
        return result
    except requests.exceptions.Timeout:
        logger.warning("VirusTotal timeout for %s", ip)
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 429:
            logger.warning("VirusTotal rate limit hit. Sleeping 60s.")
            time.sleep(60)
        else:
            logger.error("VirusTotal HTTP error for %s: %s", ip, exc)
    except Exception as exc:
        logger.error("VirusTotal unexpected error for %s: %s", ip, exc)

    return empty_result


def query_virustotal_hash(file_hash: str) -> Dict[str, Any]:
    """
    Query VirusTotal v3 for a file hash (MD5/SHA1/SHA256).
    Returns detection count across all AV engines.
    """
    empty_result = {"vt_hash_malicious": 0, "vt_hash_found": False}

    if not VIRUSTOTAL_API_KEY or not file_hash:
        return empty_result

    cache_key = f"virustotal:hash:{file_hash}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    time.sleep(VIRUSTOTAL_RATE_LIMIT_DELAY)

    try:
        resp = _session.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        if resp.status_code == 404:
            _cache_set(cache_key, empty_result)
            return empty_result
        resp.raise_for_status()
        stats = (
            resp.json().get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        result = {
            "vt_hash_malicious": stats.get("malicious", 0),
            "vt_hash_found": True,
        }
        _cache_set(cache_key, result)
        return result
    except Exception as exc:
        logger.error("VirusTotal hash lookup error for %s: %s", file_hash, exc)
        return empty_result

# ─── MITRE ATT&CK MAPPING ────────────────────────────────────────────────────

def map_mitre_attack(alert_category: str) -> Dict[str, str]:
    """
    Map a Suricata alert category to a MITRE ATT&CK tactic and technique.
    Falls back to Unknown if no mapping exists.
    """
    # Try exact match first
    mapping = MITRE_ATTACK_MAPPING.get(alert_category)
    if mapping:
        return mapping

    # Try partial/substring match
    for category_key, mapping_val in MITRE_ATTACK_MAPPING.items():
        if category_key.lower() in alert_category.lower():
            return mapping_val

    return _MITRE_FALLBACK

# ─── MAIN ENRICHMENT FUNCTION ────────────────────────────────────────────────

def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a raw Suricata alert with:
      - AbuseIPDB IP reputation (source IP)
      - VirusTotal IP analysis (source IP)
      - VirusTotal file hash lookup (if present)
      - MITRE ATT&CK technique mapping
      - Enrichment metadata (timestamp, enrichment version)

    Modifies alert in-place and returns it.
    """
    src_ip: str = alert.get("src_ip", "0.0.0.0")
    alert_category: str = alert.get("alert_category", "")
    file_hash: str = alert.get("fileinfo", {}).get("sha256", "") if isinstance(alert.get("fileinfo"), dict) else ""

    # ── AbuseIPDB ──────────────────────────────────────────────────────
    abuse_data = query_abuseipdb(src_ip)

    # ── VirusTotal IP ──────────────────────────────────────────────────
    vt_ip_data = query_virustotal_ip(src_ip)

    # ── VirusTotal Hash (optional) ────────────────────────────────────
    vt_hash_data = {}
    if file_hash:
        vt_hash_data = query_virustotal_hash(file_hash)

    # ── MITRE ATT&CK ──────────────────────────────────────────────────
    mitre = map_mitre_attack(alert_category)

    # ── Compose enrichment payload ────────────────────────────────────
    alert["enrichment"] = {
        # AbuseIPDB fields
        "abuse_confidence_score": abuse_data["abuse_confidence_score"],
        "abuse_total_reports": abuse_data["total_reports"],
        "src_country_code": abuse_data["country_code"],
        "src_isp": abuse_data["isp"],
        "src_usage_type": abuse_data["usage_type"],
        "is_tor_exit": abuse_data["is_tor"],
        # VirusTotal IP fields
        "vt_malicious_count": vt_ip_data["vt_malicious_count"],
        "vt_suspicious_count": vt_ip_data["vt_suspicious_count"],
        "vt_reputation": vt_ip_data["vt_reputation"],
        # VirusTotal hash fields (if present)
        **vt_hash_data,
        # Metadata
        "enriched_at": datetime.now(timezone.utc).isoformat(),
        "enrichment_version": "2.0",
    }

    # ── MITRE ATT&CK ──────────────────────────────────────────────────
    alert["mitre"] = {
        "tactic": mitre["tactic"],
        "technique_id": mitre["technique_id"],
        "technique_name": mitre["technique_name"],
        "attack_url": f"https://attack.mitre.org/techniques/{mitre['technique_id']}/",
    }

    logger.debug(
        "Enriched alert from %s | abuse=%d | vt=%d | mitre=%s",
        src_ip,
        abuse_data["abuse_confidence_score"],
        vt_ip_data["vt_malicious_count"],
        mitre["technique_id"],
    )

    return alert


def get_cache_stats() -> Dict[str, int]:
    """Return current in-memory cache statistics."""
    now = time.time()
    active = sum(
        1 for _, (_, cached_at) in _memory_cache.items()
        if now - cached_at < CACHE_TTL
    )
    return {
        "total_entries": len(_memory_cache),
        "active_entries": active,
        "expired_entries": len(_memory_cache) - active,
    }
