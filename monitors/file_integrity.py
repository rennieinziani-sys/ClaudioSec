"""
ClaudioSec - File Integrity Monitor
SHA256 hash tracking, tamper detection, and baseline management
"""

import asyncio
import hashlib
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set
from loguru import logger

from core.database import insert_event, upsert_file_hash, get_file_hash

# Directories to monitor
DEFAULT_WATCHED_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
WATCHED_DIRS = os.getenv("WATCHED_DIRS", ",".join(DEFAULT_WATCHED_DIRS)).split(",")

# Extensions to skip
SKIP_EXTENSIONS = {".log", ".tmp", ".pid", ".lock", ".swp", ".pyc", ".cache"}
# Directories to skip
SKIP_DIRS = {"/etc/mtab", "/etc/resolv.conf.d", "/proc", "/sys", "/dev"}

# Max file size to hash (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024


def _compute_sha256(file_path: str) -> Optional[str]:
    """Compute SHA256 hash of a file"""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _get_file_info(file_path: str) -> Optional[dict]:
    """Get file metadata"""
    try:
        stat_info = os.stat(file_path)
        return {
            "size": stat_info.st_size,
            "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            "mode": oct(stat_info.st_mode),
            "uid": stat_info.st_uid,
            "gid": stat_info.st_gid,
        }
    except Exception:
        return None


async def _scan_file(file_path: str, baseline_mode: bool = False) -> bool:
    """
    Scan a single file.
    In baseline_mode: store the hash.
    In check_mode: compare against stored hash.
    Returns True if a change was detected.
    """
    path = Path(file_path)

    # Skip checks
    if not path.is_file():
        return False
    if path.suffix in SKIP_EXTENSIONS:
        return False
    if path.stat().st_size > MAX_FILE_SIZE:
        return False

    sha256 = _compute_sha256(file_path)
    if not sha256:
        return False

    info = _get_file_info(file_path)
    if not info:
        return False

    if baseline_mode:
        await upsert_file_hash(file_path, sha256, info["size"], info["modified"])
        return False

    # Check against stored hash
    stored = await get_file_hash(file_path)

    if stored is None:
        # New file detected
        await insert_event(
            event_type="new_file_detected",
            severity="medium",
            source_module="file_integrity",
            title=f"New File Detected: {file_path}",
            description=f"A new file was detected that was not in the baseline: {file_path}",
            file_path=file_path,
            raw_data={"hash": sha256, "size": info["size"], "mode": info["mode"]},
        )
        # Add to baseline
        await upsert_file_hash(file_path, sha256, info["size"], info["modified"])
        return True

    if stored["hash_sha256"] != sha256:
        # File modified!
        severity = "critical" if _is_critical_file(file_path) else "high"
        await insert_event(
            event_type="file_modified",
            severity=severity,
            source_module="file_integrity",
            title=f"File Modified: {file_path}",
            description=(
                f"File integrity violation detected. File has been modified.\n"
                f"Path: {file_path}\n"
                f"Old hash: {stored['hash_sha256']}\n"
                f"New hash: {sha256}\n"
                f"Last baseline: {stored.get('baseline_set_at', 'unknown')}"
            ),
            file_path=file_path,
            raw_data={
                "old_hash": stored["hash_sha256"],
                "new_hash": sha256,
                "old_size": stored.get("file_size"),
                "new_size": info["size"],
                "modified": info["modified"],
            },
        )
        logger.warning(f"[FIM] File modified: {file_path}")
        # Update hash
        await upsert_file_hash(file_path, sha256, info["size"], info["modified"])
        return True

    return False


def _is_critical_file(file_path: str) -> bool:
    """Check if a file is considered critical"""
    critical_patterns = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
        "/root/.ssh/", "/.bashrc", "/.bash_profile", "/.profile",
        "/usr/bin/sudo", "/usr/bin/su", "/bin/bash", "/bin/sh",
        "/etc/crontab", "/etc/cron", "/etc/hosts",
    ]
    return any(pattern in file_path for pattern in critical_patterns)


async def _check_permissions(file_path: str):
    """Check for dangerous file permissions"""
    try:
        st = os.stat(file_path)
        mode = stat.filemode(st.st_mode)

        # World-writable files in system dirs
        if st.st_mode & stat.S_IWOTH:
            severity = "critical" if _is_critical_file(file_path) else "high"
            await insert_event(
                event_type="dangerous_permissions",
                severity=severity,
                source_module="file_integrity",
                title=f"World-Writable File: {file_path}",
                description=f"File {file_path} has world-writable permissions ({mode}). This is a security risk.",
                file_path=file_path,
                raw_data={"mode": mode, "uid": st.st_uid, "gid": st.st_gid},
            )

        # SUID/SGID on unexpected files
        if (st.st_mode & stat.S_ISUID) and file_path not in _known_suid_binaries():
            await insert_event(
                event_type="suid_binary",
                severity="high",
                source_module="file_integrity",
                title=f"SUID Binary Detected: {file_path}",
                description=f"File {file_path} has SUID bit set ({mode}). Verify this is expected.",
                file_path=file_path,
                raw_data={"mode": mode},
            )

    except Exception:
        pass


def _known_suid_binaries() -> List[str]:
    return [
        "/usr/bin/sudo", "/usr/bin/su", "/bin/su",
        "/usr/bin/passwd", "/usr/bin/gpasswd",
        "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
    ]


async def scan_directory(directory: str, baseline_mode: bool = False) -> int:
    """Scan all files in a directory"""
    path = Path(directory)
    if not path.exists():
        return 0

    count = 0
    for file_path in path.rglob("*"):
        str_path = str(file_path)
        if any(skip in str_path for skip in SKIP_DIRS):
            continue
        if file_path.is_file():
            try:
                changed = await _scan_file(str_path, baseline_mode)
                await _check_permissions(str_path)
                count += 1
                if count % 100 == 0:
                    await asyncio.sleep(0)  # Yield to event loop
            except Exception as e:
                logger.debug(f"[FIM] Error scanning {str_path}: {e}")

    return count


async def set_baseline():
    """Set the initial file integrity baseline"""
    logger.info("[FIM] Setting file integrity baseline...")
    total = 0
    for directory in WATCHED_DIRS:
        count = await scan_directory(directory, baseline_mode=True)
        total += count
        logger.info(f"[FIM] Baseline: {count} files in {directory}")
    logger.info(f"[FIM] Baseline complete: {total} files hashed")


async def check_integrity():
    """Run a full integrity check against baseline"""
    logger.info("[FIM] Running integrity check...")
    violations = 0
    for directory in WATCHED_DIRS:
        path = Path(directory)
        if not path.exists():
            continue
        for file_path in path.rglob("*"):
            if file_path.is_file():
                try:
                    changed = await _scan_file(str(file_path))
                    if changed:
                        violations += 1
                    await asyncio.sleep(0)
                except Exception:
                    pass
    logger.info(f"[FIM] Integrity check complete: {violations} violations found")
    return violations


async def start_file_integrity_monitor(check_interval: int = 300):
    """
    Start file integrity monitoring.
    Sets baseline on first run, then checks every `check_interval` seconds.
    """
    # Check if any dirs exist
    existing = [d for d in WATCHED_DIRS if Path(d).exists()]

    if not existing:
        logger.warning("[FIM] No watched directories found — running in simulation mode")
        await _simulate_fim_events()
        return

    # Set baseline
    await set_baseline()

    logger.info(f"[FIM] Monitoring {len(existing)} directories (check every {check_interval}s)")

    while True:
        await asyncio.sleep(check_interval)
        await check_integrity()


async def _simulate_fim_events():
    """Simulate file integrity events for testing"""
    import random

    logger.info("[FIM] Running in simulation mode")

    sim_events = [
        {
            "event_type": "file_modified",
            "severity": "critical",
            "title": "File Modified: /etc/passwd",
            "description": "File integrity violation: /etc/passwd was modified. Old hash: abc123. New hash: def456.",
            "file_path": "/etc/passwd",
            "raw_data": {"old_hash": "abc123abc123", "new_hash": "def456def456", "simulated": True},
        },
        {
            "event_type": "new_file_detected",
            "severity": "medium",
            "title": "New File: /usr/bin/backdoor",
            "description": "New file detected in system binary directory: /usr/bin/backdoor",
            "file_path": "/usr/bin/backdoor",
            "raw_data": {"hash": "badbadbadbad", "simulated": True},
        },
        {
            "event_type": "suid_binary",
            "severity": "high",
            "title": "SUID Binary Detected: /tmp/rootkit",
            "description": "Unexpected SUID binary detected at /tmp/rootkit",
            "file_path": "/tmp/rootkit",
            "raw_data": {"mode": "-rwsr-xr-x", "simulated": True},
        },
    ]

    while True:
        await asyncio.sleep(random.randint(20, 60))
        event = random.choice(sim_events)
        await insert_event(
            source_module="file_integrity",
            **event,
        )
        logger.info("[FIM SIM] Simulated FIM event generated")