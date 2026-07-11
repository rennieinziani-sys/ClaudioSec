"""
ClaudioSec - Test Suite
"""

import pytest
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DB_PATH"] = "/tmp/claudiosec_test.db"
os.environ["ANTHROPIC_API_KEY"] = os.getenv("ANTHROPIC_API_KEY", "test-key")

from core.database import init_db, insert_event, get_events, get_event_stats, mark_event_resolved
from httpx import AsyncClient, ASGITransport


@pytest.fixture(autouse=True)
def setup_db():
    """Fresh DB for each test"""
    if os.path.exists("/tmp/claudiosec_test.db"):
        os.remove("/tmp/claudiosec_test.db")
    init_db()


@pytest.mark.asyncio
async def test_insert_event():
    event_id = await insert_event(
        event_type="port_scan",
        severity="high",
        source_module="network_monitor",
        title="Test Port Scan",
        description="Test description",
        source_ip="1.2.3.4",
    )
    assert event_id is not None
    assert event_id > 0


@pytest.mark.asyncio
async def test_get_events():
    await insert_event("brute_force", "critical", "auth_monitor", "Test Brute Force", "desc")
    await insert_event("file_modified", "high", "file_integrity", "Test File Modified", "desc")

    events = await get_events(limit=10)
    assert len(events) >= 2


@pytest.mark.asyncio
async def test_event_severity_filter():
    await insert_event("test_low", "low", "test", "Low Event", "desc")
    await insert_event("test_critical", "critical", "test", "Critical Event", "desc")

    critical = await get_events(severity="critical")
    assert all(e["severity"] == "critical" for e in critical)

    low = await get_events(severity="low")
    assert all(e["severity"] == "low" for e in low)


@pytest.mark.asyncio
async def test_resolve_event():
    event_id = await insert_event("test", "medium", "test", "Test", "desc")
    await mark_event_resolved(event_id)

    resolved = await get_events(resolved=True)
    ids = [e["id"] for e in resolved]
    assert event_id in ids


@pytest.mark.asyncio
async def test_event_stats():
    await insert_event("t1", "critical", "mod", "Critical 1", "d")
    await insert_event("t2", "high", "mod", "High 1", "d")
    await insert_event("t3", "medium", "mod", "Medium 1", "d")

    stats = await get_event_stats()
    assert stats["total_events"] >= 3
    assert "by_severity" in stats
    assert stats["by_severity"].get("critical", 0) >= 1


@pytest.mark.asyncio
async def test_api_stats_endpoint():
    from api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_events" in data


@pytest.mark.asyncio
async def test_api_events_endpoint():
    from api.main import app
    await insert_event("port_scan", "high", "network_monitor", "Test Event", "desc", source_ip="5.5.5.5")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/events?limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data


@pytest.mark.asyncio
async def test_api_create_manual_event():
    from api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/events/manual", json={
            "event_type": "test_event",
            "severity": "medium",
            "title": "Manual Test Event",
            "description": "Created via API test",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "event_id" in data


@pytest.mark.asyncio
async def test_api_resolve_event():
    from api.main import app
    event_id = await insert_event("test", "low", "test", "To Resolve", "desc")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(f"/api/events/{event_id}/resolve")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "resolved"


@pytest.mark.asyncio
async def test_api_threat_ip():
    from api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/threat-intel/ip", json={
            "ip": "192.0.2.100",
            "threat_type": "scanner",
            "confidence": 95,
            "source": "test",
        })
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_log_pattern_matching():
    """Test log analyzer pattern detection"""
    from monitors.log_analyzer import _process_log_line

    # SSH failed login
    await _process_log_line(
        "Jun 13 10:00:00 host sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "/var/log/auth.log"
    )
    events = await get_events(event_type="failed_auth")
    assert len(events) >= 1
    assert events[0]["source_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_file_hash_tracking():
    """Test file integrity hash functions"""
    import tempfile
    import hashlib
    from core.database import upsert_file_hash, get_file_hash

    # Create temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"test content")
        tmp_path = f.name

    h = hashlib.sha256(b"test content").hexdigest()
    await upsert_file_hash(tmp_path, h, 12, "2024-01-01")

    stored = await get_file_hash(tmp_path)
    assert stored is not None
    assert stored["hash_sha256"] == h

    os.unlink(tmp_path)