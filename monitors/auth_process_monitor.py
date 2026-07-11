"""
ClaudioSec - Auth & Process Monitor
Failed logins, SSH brute force, privilege escalation, suspicious processes
"""

import asyncio
import os
import psutil
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set
from loguru import logger

from core.database import insert_event

# Config
FAILED_LOGIN_THRESHOLD = int(os.getenv("FAILED_LOGIN_THRESHOLD", 5))

# Track failed logins: {(username, ip): [timestamps]}
_failed_logins: Dict = defaultdict(list)
# Known suspicious process names
_known_suspicious_procs: Set[str] = {
    "nmap", "masscan", "nikto", "sqlmap", "metasploit",
    "msfconsole", "msfvenom", "hydra", "medusa", "john",
    "hashcat", "aircrack-ng", "wireshark", "tcpdump",
    "netcat", "nc", "ncat", "socat", "cryptominer",
    "xmrig", "minerd", "cpuminer", "ettercap", "bettercap",
}
# Previously seen PIDs to detect new processes
_seen_pids: Set[int] = set()
# High CPU processes to track
_high_cpu_procs: Dict[int, int] = {}  # pid: count of high cpu readings


async def check_failed_logins(username: str, source_ip: str):
    """Track failed login attempts and alert on threshold breach"""
    import time
    key = (username, source_ip)
    now = time.time()

    tracker = _failed_logins[key]
    # Keep last 10 minutes
    tracker[:] = [ts for ts in tracker if now - ts < 600]
    tracker.append(now)

    if len(tracker) >= FAILED_LOGIN_THRESHOLD:
        await insert_event(
            event_type="brute_force",
            severity="high",
            source_module="auth_monitor",
            title=f"Brute Force Detected: {username} from {source_ip}",
            description=(
                f"IP {source_ip} made {len(tracker)} failed login attempts for user '{username}' "
                f"in the last 10 minutes. Possible brute force attack."
            ),
            username=username,
            source_ip=source_ip,
            raw_data={"attempt_count": len(tracker), "threshold": FAILED_LOGIN_THRESHOLD},
        )
        logger.warning(f"[Auth] Brute force: {username}@{source_ip} ({len(tracker)} attempts)")
        _failed_logins[key] = []  # Reset after alert


async def _scan_processes():
    """Scan running processes for suspicious activity"""
    global _seen_pids

    current_pids = set()

    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "status", "ppid"]):
        try:
            info = proc.info
            pid = info["pid"]
            name = (info.get("name") or "").lower()
            username = info.get("username") or ""
            cmdline = " ".join(info.get("cmdline") or [])

            current_pids.add(pid)

            # New process detection
            if pid not in _seen_pids:
                # Check if suspicious
                if name in _known_suspicious_procs:
                    await insert_event(
                        event_type="suspicious_process",
                        severity="high",
                        source_module="process_monitor",
                        title=f"Suspicious Process: {name} (PID {pid})",
                        description=f"Known hacking/scanning tool detected: '{name}' (PID {pid}) run by '{username}'.\nCommand: {cmdline[:200]}",
                        username=username,
                        process_name=name,
                        raw_data={"pid": pid, "cmdline": cmdline[:500], "ppid": info.get("ppid")},
                    )
                    logger.warning(f"[Process] Suspicious process: {name} PID={pid}")

                # Root process from unexpected location
                if username == "root" and cmdline and "/tmp/" in cmdline:
                    await insert_event(
                        event_type="suspicious_process",
                        severity="critical",
                        source_module="process_monitor",
                        title=f"Root Process from /tmp: {name}",
                        description=f"A root-owned process is executing from /tmp directory: {cmdline[:200]}",
                        username=username,
                        process_name=name,
                        raw_data={"pid": pid, "cmdline": cmdline[:500]},
                    )

            # CPU usage check (possible cryptominer)
            cpu = info.get("cpu_percent") or 0
            if cpu > 90:
                _high_cpu_procs[pid] = _high_cpu_procs.get(pid, 0) + 1
                if _high_cpu_procs[pid] == 3:  # Sustained high CPU for 3 checks
                    await insert_event(
                        event_type="high_cpu_process",
                        severity="medium",
                        source_module="process_monitor",
                        title=f"Sustained High CPU: {name} ({cpu:.1f}%)",
                        description=(
                            f"Process '{name}' (PID {pid}, user '{username}') has maintained >{90}% CPU "
                            f"usage across multiple checks. Possible cryptominer or runaway process."
                        ),
                        username=username,
                        process_name=name,
                        raw_data={"pid": pid, "cpu_percent": cpu, "cmdline": cmdline[:300]},
                    )
            else:
                _high_cpu_procs.pop(pid, None)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Detect killed processes (cleanup)
    _seen_pids = current_pids


async def _check_open_ports():
    """Check for unexpected listening ports"""
    try:
        connections = psutil.net_connections(kind="inet")
        listening = [c for c in connections if c.status == "LISTEN"]

        # Known safe ports
        known_ports = {22, 80, 443, 8080, 8443, 3000, 5000, 8000, 53, 123, 5432, 3306}

        for conn in listening:
            port = conn.laddr.port if conn.laddr else None
            if port and port not in known_ports and port < 1024:
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    proc_name = proc.name() if proc else "unknown"
                    username = proc.username() if proc else "unknown"
                except Exception:
                    proc_name = "unknown"
                    username = "unknown"

                await insert_event(
                    event_type="unexpected_listener",
                    severity="medium",
                    source_module="process_monitor",
                    title=f"Unexpected Listener on Port {port}",
                    description=f"Unexpected service listening on privileged port {port}. Process: {proc_name} (user: {username})",
                    process_name=proc_name,
                    raw_data={"port": port, "pid": conn.pid, "process": proc_name, "user": username},
                )

    except Exception as e:
        logger.debug(f"[Process] Port check error: {e}")


async def _collect_system_stats():
    """Collect and store system resource stats"""
    from core.database import get_db_path
    import aiosqlite

    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        net = psutil.net_io_counters()
        connections = len(psutil.net_connections())

        async with aiosqlite.connect(get_db_path()) as db:
            await db.execute(
                """
                INSERT INTO system_stats (timestamp, cpu_percent, memory_percent, disk_percent,
                    network_bytes_sent, network_bytes_recv, active_connections)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat(),
                    cpu, mem, disk,
                    net.bytes_sent, net.bytes_recv,
                    connections,
                ),
            )
            await db.commit()

        # Alert on disk full
        if disk > 90:
            await insert_event(
                event_type="disk_critical",
                severity="high",
                source_module="process_monitor",
                title=f"Disk Usage Critical: {disk:.1f}%",
                description=f"Root filesystem usage is at {disk:.1f}%. System may become unstable.",
                raw_data={"disk_percent": disk},
            )

        # Alert on memory pressure
        if mem > 95:
            await insert_event(
                event_type="memory_critical",
                severity="high",
                source_module="process_monitor",
                title=f"Memory Usage Critical: {mem:.1f}%",
                description=f"System memory usage is at {mem:.1f}%. OOM kills may occur.",
                raw_data={"memory_percent": mem},
            )

    except Exception as e:
        logger.error(f"[Process] Stats collection error: {e}")


async def start_auth_process_monitor(scan_interval: int = 10):
    """Start auth and process monitoring loops"""
    logger.info(f"[Auth/Process] Monitor started (interval={scan_interval}s)")

    cycle = 0
    while True:
        await asyncio.sleep(scan_interval)

        try:
            await _scan_processes()
        except Exception as e:
            logger.error(f"[Process] Scan error: {e}")

        # Less frequent checks
        cycle += 1
        if cycle % 6 == 0:  # Every ~60s
            await _check_open_ports()
        if cycle % 3 == 0:  # Every ~30s
            await _collect_system_stats()