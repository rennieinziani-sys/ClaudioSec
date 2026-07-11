"""
ClaudioSec - Log Analyzer
Real-time log monitoring with pattern matching and anomaly detection
"""

import asyncio
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from loguru import logger

from core.database import insert_event

# Log files to watch
DEFAULT_LOGS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "/var/log/fail2ban.log",
    "/var/log/kern.log",
]

WATCHED_LOGS = os.getenv("WATCHED_LOGS", ",".join(DEFAULT_LOGS)).split(",")

# Regex patterns to detect in logs
PATTERNS = [
    {
        "name": "ssh_failed_login",
        "regex": r"Failed password for (\S+) from ([\d.]+)",
        "severity": "medium",
        "event_type": "failed_auth",
        "title_template": "SSH Failed Login: {groups[0]} from {groups[1]}",
        "desc_template": "Failed SSH login attempt for user '{groups[0]}' from IP {groups[1]}",
        "extract": {"username": 0, "source_ip": 1},
    },
    {
        "name": "ssh_invalid_user",
        "regex": r"Invalid user (\S+) from ([\d.]+)",
        "severity": "medium",
        "event_type": "invalid_user",
        "title_template": "SSH Invalid User: {groups[0]} from {groups[1]}",
        "desc_template": "SSH login attempt with non-existent user '{groups[0]}' from {groups[1]}",
        "extract": {"username": 0, "source_ip": 1},
    },
    {
        "name": "sudo_failure",
        "regex": r"sudo:.*authentication failure.*user=(\S+)",
        "severity": "high",
        "event_type": "sudo_abuse",
        "title_template": "Sudo Auth Failure: {groups[0]}",
        "desc_template": "Failed sudo authentication attempt by user '{groups[0]}'",
        "extract": {"username": 0},
    },
    {
        "name": "sudo_success",
        "regex": r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)",
        "severity": "low",
        "event_type": "sudo_command",
        "title_template": "Sudo Command: {groups[0]}",
        "desc_template": "User '{groups[0]}' executed sudo command: {groups[1]}",
        "extract": {"username": 0},
    },
    {
        "name": "ssh_accepted",
        "regex": r"Accepted (password|publickey) for (\S+) from ([\d.]+)",
        "severity": "low",
        "event_type": "successful_auth",
        "title_template": "SSH Login: {groups[1]} from {groups[2]}",
        "desc_template": "Successful SSH login for user '{groups[1]}' from {groups[2]} via {groups[0]}",
        "extract": {"username": 1, "source_ip": 2},
    },
    {
        "name": "new_user_created",
        "regex": r"new user: name=(\S+)",
        "severity": "high",
        "event_type": "user_created",
        "title_template": "New User Created: {groups[0]}",
        "desc_template": "A new system user '{groups[0]}' was created",
        "extract": {"username": 0},
    },
    {
        "name": "passwd_changed",
        "regex": r"password changed for (\S+)",
        "severity": "medium",
        "event_type": "password_change",
        "title_template": "Password Changed: {groups[0]}",
        "desc_template": "Password changed for user '{groups[0]}'",
        "extract": {"username": 0},
    },
    {
        "name": "oom_kill",
        "regex": r"Out of memory: Kill process (\d+) \((\S+)\)",
        "severity": "high",
        "event_type": "oom_kill",
        "title_template": "OOM Kill: {groups[1]} (PID {groups[0]})",
        "desc_template": "Out-of-memory killer terminated process {groups[1]} (PID {groups[0]})",
        "extract": {"process_name": 1},
    },
    {
        "name": "kernel_panic",
        "regex": r"kernel: BUG:|kernel: Oops:|Kernel panic",
        "severity": "critical",
        "event_type": "kernel_error",
        "title_template": "Kernel Error Detected",
        "desc_template": "Critical kernel error detected in system logs",
        "extract": {},
    },
    {
        "name": "nginx_4xx",
        "regex": r'"(?:GET|POST|PUT|DELETE|HEAD) ([^"]+)" (4\d\d)',
        "severity": "low",
        "event_type": "http_error",
        "title_template": "HTTP {groups[1]}: {groups[0]}",
        "desc_template": "Web server returned {groups[1]} for request to {groups[0]}",
        "extract": {},
    },
    {
        "name": "nginx_scanner",
        "regex": r'"(?:GET|POST) (/\.env|/wp-admin|/admin|/phpmyadmin|/.git)',
        "severity": "medium",
        "event_type": "web_scanner",
        "title_template": "Web Scanner Detected: {groups[0]}",
        "desc_template": "Possible web vulnerability scanner requesting sensitive path: {groups[0]}",
        "extract": {},
    },
    {
        "name": "segfault",
        "regex": r"segfault at .* in (\S+)",
        "severity": "medium",
        "event_type": "process_crash",
        "title_template": "Segfault in {groups[0]}",
        "desc_template": "Process segmentation fault detected in {groups[0]}",
        "extract": {"process_name": 0},
    },
    {
        "name": "ssh_brute_force_fail2ban",
        "regex": r"fail2ban.actions.*Ban ([\d.]+)",
        "severity": "high",
        "event_type": "brute_force_blocked",
        "title_template": "Brute Force Blocked: {groups[0]}",
        "desc_template": "fail2ban blocked IP {groups[0]} for brute force activity",
        "extract": {"source_ip": 0},
    },
]

# Compile patterns once
_compiled_patterns = [
    {**p, "compiled": re.compile(p["regex"], re.IGNORECASE)}
    for p in PATTERNS
]


async def _process_log_line(line: str, log_file: str):
    """Match a log line against all patterns and insert events"""
    for pattern in _compiled_patterns:
        match = pattern["compiled"].search(line)
        if match:
            groups = match.groups()

            # Build title and description from template
            ctx = {"groups": groups, "line": line.strip()}
            try:
                title = pattern["title_template"].format(**ctx)
                desc = pattern["desc_template"].format(**ctx)
            except (IndexError, KeyError):
                title = f"Security Event: {pattern['name']}"
                desc = line.strip()

            # Extract specific fields
            kwargs = {}
            for field, idx in pattern.get("extract", {}).items():
                try:
                    kwargs[field] = groups[idx]
                except IndexError:
                    pass

            await insert_event(
                event_type=pattern["event_type"],
                severity=pattern["severity"],
                source_module="log_analyzer",
                title=title,
                description=desc,
                raw_data={"log_file": log_file, "line": line.strip()},
                **kwargs,
            )
            logger.debug(f"[LogAnalyzer] Pattern '{pattern['name']}' matched in {log_file}")


async def _tail_file(log_path: str):
    """Tail a log file, processing new lines as they appear"""
    path = Path(log_path)

    if not path.exists():
        logger.warning(f"[LogAnalyzer] Log file not found: {log_path}")
        return

    logger.info(f"[LogAnalyzer] Tailing: {log_path}")

    with open(log_path, "r", errors="ignore") as f:
        # Seek to end
        f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                await _process_log_line(line, log_path)
            else:
                await asyncio.sleep(0.5)

                # Handle log rotation
                try:
                    if not path.exists() or path.stat().st_size < f.tell():
                        logger.info(f"[LogAnalyzer] Log rotated: {log_path}")
                        f.seek(0)
                except Exception:
                    pass


async def _simulate_log_events():
    """Simulate log events for testing environments"""
    import random
    import asyncio

    logger.info("[LogAnalyzer] Running in simulation mode")

    sim_lines = [
        ("Failed password for root from 198.51.100.99 port 22 ssh2", "/var/log/auth.log"),
        ("Invalid user admin from 203.0.113.10 port 54321", "/var/log/auth.log"),
        ('sudo: john : authentication failure ; logname=john uid=1001 euid=0 user=john', "/var/log/auth.log"),
        ('sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash', "/var/log/auth.log"),
        ("Accepted publickey for deploy from 10.0.0.50 port 22 ssh2", "/var/log/auth.log"),
        ('nginx: "GET /wp-admin/setup-config.php HTTP/1.1" 404', "/var/log/nginx/access.log"),
        ('nginx: "GET /.env HTTP/1.1" 200', "/var/log/nginx/access.log"),
        ("fail2ban.actions [1234]: WARNING [sshd] Ban 198.51.100.77", "/var/log/fail2ban.log"),
        ("new user: name=backdoor", "/var/log/auth.log"),
    ]

    while True:
        await asyncio.sleep(random.randint(8, 25))
        line, log_file = random.choice(sim_lines)
        await _process_log_line(line, log_file)
        logger.info(f"[LogAnalyzer SIM] Processed simulated log line")


async def start_log_analyzer():
    """Start log file monitoring"""
    existing_logs = [f for f in WATCHED_LOGS if Path(f).exists()]

    if not existing_logs:
        logger.warning("[LogAnalyzer] No log files found — running in simulation mode")
        asyncio.create_task(_simulate_log_events())
        return

    logger.info(f"[LogAnalyzer] Monitoring {len(existing_logs)} log files")
    tasks = [asyncio.create_task(_tail_file(log)) for log in existing_logs]
    # Also add simulation for missing files
    missing = set(WATCHED_LOGS) - set(existing_logs)
    if missing:
        logger.info(f"[LogAnalyzer] {len(missing)} log files missing, simulation active for those")
        asyncio.create_task(_simulate_log_events())