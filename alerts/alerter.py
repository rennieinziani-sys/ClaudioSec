"""
ClaudioSec - Alert System
Slack and webhook notifications for security events
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Dict, Optional
from loguru import logger
import httpx

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

# Severity → Slack color
SEVERITY_COLORS = {
    "low": "#36a64f",       # green
    "medium": "#ff9900",    # orange
    "high": "#e01e5a",      # red
    "critical": "#8b0000",  # dark red
}

SEVERITY_EMOJI = {
    "low": "ℹ️",
    "medium": "⚠️",
    "high": "🚨",
    "critical": "🔴",
}

# Rate limiting: avoid spamming on high event volumes
_last_alert_time: Dict[str, float] = {}
_alert_cooldown: Dict[str, int] = {
    "low": 300,      # 5 min cooldown for low severity
    "medium": 120,   # 2 min
    "high": 30,      # 30s
    "critical": 0,   # Always send critical
}


def _should_send_alert(key: str, severity: str) -> bool:
    """Rate limit alerts to avoid flooding"""
    import time
    now = time.time()
    cooldown = _alert_cooldown.get(severity, 60)
    last = _last_alert_time.get(key, 0)

    if now - last >= cooldown:
        _last_alert_time[key] = now
        return True
    return False


async def send_slack_alert(event: Dict, ai_analysis: Optional[Dict] = None):
    """Send a security alert to Slack"""
    if not SLACK_WEBHOOK_URL:
        logger.debug("[Alerts] Slack webhook not configured")
        return

    severity = event.get("severity", "medium")
    rate_key = f"slack_{event.get('event_type', 'unknown')}_{event.get('source_ip', '')}"

    if not _should_send_alert(rate_key, severity):
        return

    emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    color = SEVERITY_COLORS.get(severity, "#ff9900")

    # Build Slack message
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} ClaudioSec Alert: {event.get('title', 'Security Event')}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Module:*\n{event.get('source_module', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*Event Type:*\n{event.get('event_type', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*Time:*\n{event.get('timestamp', datetime.utcnow().isoformat())}"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{event.get('description', '')[:500]}"},
        },
    ]

    # Add source/dest IP if present
    if event.get("source_ip") or event.get("destination_ip"):
        ip_text = ""
        if event.get("source_ip"):
            ip_text += f"*Source IP:* {event['source_ip']}\n"
        if event.get("destination_ip"):
            ip_text += f"*Dest IP:* {event['destination_ip']}"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": ip_text}})

    # Add AI analysis if available
    if ai_analysis:
        ai_text = (
            f"*🤖 AI Analysis:*\n"
            f"Threat: {ai_analysis.get('threat_type', 'unknown')} "
            f"(confidence: {ai_analysis.get('confidence', 0)}%)\n"
            f"{ai_analysis.get('summary', '')}\n"
            f"*Immediate Action:* {ai_analysis.get('immediate_action', 'Investigate manually')}"
        )
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": ai_text}})

    blocks.append({"type": "divider"})

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
                "fallback": f"[{severity.upper()}] {event.get('title', 'Security Alert')}",
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(SLACK_WEBHOOK_URL, json=payload)
            if resp.status_code == 200:
                logger.info(f"[Alerts] Slack alert sent: {event.get('title')}")
            else:
                logger.error(f"[Alerts] Slack error: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.error(f"[Alerts] Slack send failed: {e}")


async def send_webhook_alert(event: Dict, ai_analysis: Optional[Dict] = None):
    """Send alert to generic webhook endpoint"""
    if not WEBHOOK_URL:
        return

    severity = event.get("severity", "medium")
    rate_key = f"webhook_{event.get('event_type', 'unknown')}_{event.get('source_ip', '')}"

    if not _should_send_alert(rate_key, severity):
        return

    payload = {
        "source": "claudiosec",
        "timestamp": datetime.utcnow().isoformat(),
        "event": event,
        "ai_analysis": ai_analysis,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(WEBHOOK_URL, json=payload)
            logger.info(f"[Alerts] Webhook sent: {resp.status_code}")
    except Exception as e:
        logger.error(f"[Alerts] Webhook failed: {e}")


async def send_alert(event: Dict, ai_analysis: Optional[Dict] = None):
    """Send alert via all configured channels"""
    severity = event.get("severity", "low")

    # Only alert on medium+ by default
    if severity == "low":
        return

    await asyncio.gather(
        send_slack_alert(event, ai_analysis),
        send_webhook_alert(event, ai_analysis),
        return_exceptions=True,
    )


async def send_incident_report_alert(report: Dict):
    """Send incident report notification"""
    if not SLACK_WEBHOOK_URL:
        return

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔴 New Incident Report Generated"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{report.get('title', 'Security Incident')}*\n"
                    f"Severity: *{report.get('severity', 'unknown').upper()}*\n\n"
                    f"{report.get('threat_summary', '')[:400]}"
                ),
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Attack Vector:* {report.get('attack_vector', 'Unknown')}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Immediate Remediation:*\n{str(report.get('remediation_steps', ''))[:600]}",
            },
        },
    ]

    payload = {
        "attachments": [
            {
                "color": "#8b0000",
                "blocks": blocks,
                "fallback": f"Incident Report: {report.get('title')}",
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(SLACK_WEBHOOK_URL, json=payload)
            logger.info(f"[Alerts] Incident report alert sent")
    except Exception as e:
        logger.error(f"[Alerts] Incident report alert failed: {e}")
        