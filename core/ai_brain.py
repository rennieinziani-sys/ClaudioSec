import os
import json
import asyncio
from typing import Dict, List, Optional
from datetime import datetime
from loguru import logger
from groq import AsyncGroq
from dotenv import load_dotenv
load_dotenv()

client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "llama-3.1-8b-instant"

SYSTEM_PROMPT = """You are ClaudioSec AI, an expert cybersecurity analyst embedded in a real-time security monitoring system.
You analyze security events, detect threats, and provide actionable remediation guidance.
Always structure your output as valid JSON matching the requested schema.
Never include markdown fences or extra text - pure JSON only."""


async def analyze_event(event: Dict) -> Dict:
    prompt = f"""Analyze this security event and return a JSON object with these exact fields:
{{
  "threat_level": "low|medium|high|critical",
  "threat_type": "string",
  "confidence": 0,
  "summary": "1-2 sentence threat summary",
  "immediate_action": "Single most important action",
  "false_positive_likelihood": "low|medium|high",
  "related_ttps": [],
  "remediation": []
}}

Event data:
{json.dumps(event, indent=2)}"""

    try:
        response = await client.chat.completions.create(
            model=MODEL,
            max_tokens=1000,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        raw = response.choices[0].message.content.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        return json.loads(raw)
    except Exception as e:
        logger.error(f"[AI] Event analysis failed: {e}")
        return {
            "threat_level": event.get("severity", "medium"),
            "threat_type": event.get("event_type", "unknown"),
            "confidence": 50,
            "summary": "AI analysis unavailable",
            "immediate_action": "Review event manually",
            "false_positive_likelihood": "medium",
            "related_ttps": [],
            "remediation": ["Investigate manually"],
        }


async def generate_incident_report(events: List[Dict]) -> Dict:
    prompt = f"""Generate a security incident report. Return JSON:
{{
  "title": "Descriptive incident title",
  "severity": "low|medium|high|critical",
  "threat_summary": "Executive summary",
  "affected_assets": [],
  "attack_vector": "How it occurred",
  "attack_timeline": "Brief timeline",
  "indicators": [],
  "remediation_steps": "Detailed steps",
  "prevention": "How to prevent recurrence",
  "mitre_attack": []
}}

Events ({len(events)} total):
{json.dumps(events[:10], indent=2)}"""

    try:
        response = await client.chat.completions.create(
            model=MODEL,
            max_tokens=1000,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        raw = response.choices[0].message.content.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        report = json.loads(raw)
        report["raw_events"] = events
        return report
    except Exception as e:
        logger.error(f"[AI] Report generation failed: {e}")
        return {
            "title": "Security Incident Report",
            "severity": "medium",
            "threat_summary": "Multiple security events detected.",
            "affected_assets": [],
            "attack_vector": "Unknown",
            "attack_timeline": "See raw events",
            "indicators": [],
            "remediation_steps": "Review all flagged events",
            "prevention": "Review security policies",
            "mitre_attack": [],
            "raw_events": events,
        }


async def get_remediation(event_type: str, context: Dict) -> str:
    prompt = f"""Provide remediation steps for: {event_type}
Context: {json.dumps(context)}
Return JSON: {{"immediate_steps": [], "short_term": [], "long_term": [], "commands": [], "estimated_time": ""}}"""

    try:
        response = await client.chat.completions.create(
            model=MODEL,
            max_tokens=1000,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content.strip().replace("```json", "").replace("```", "").strip()
    except Exception as e:
        return json.dumps({
            "immediate_steps": ["Investigate manually"],
            "short_term": [],
            "long_term": [],
            "commands": [],
            "estimated_time": "Unknown",
        })


async def chat_with_analyst(conversation: List[Dict], system_context: Optional[Dict] = None) -> str:
    system = """You are ClaudioSec AI, an expert cybersecurity analyst.
Help the security team investigate and respond to threats. Respond naturally."""

    if system_context:
        stats = system_context.get("stats", {})
        system += (
            f"\n\nCurrent system state:"
            f"\n- Total events: {stats.get('total_events', 0)}"
            f"\n- Unresolved: {stats.get('unresolved', 0)}"
            f"\n- Critical unresolved: {stats.get('critical_unresolved', 0)}"
        )

    messages = [{"role": "system", "content": system}] + conversation
    try:
        response = await client.chat.completions.create(
            model=MODEL,
            max_tokens=1000,
            messages=messages,
        )
        return response.choices[0].message.content
    except Exception as e:
        return "AI analyst temporarily unavailable."


async def get_event_stats():
    from core.database import get_event_stats as _get_stats
    return await _get_stats()


async def run_ai_analysis_loop(interval: int = 30):
    from core.database import get_events, save_ai_analysis, save_incident_report
    logger.info(f"[AI] Groq analysis loop started (interval={interval}s)")
    while True:
        try:
            events = await get_events(limit=20, resolved=False)
            unanalyzed = [
                e for e in events
                if not e.get("ai_analyzed") and e.get("severity") in ("medium", "high", "critical")
            ]
            for event in unanalyzed[:5]:
                analysis = await analyze_event(event)
                await save_ai_analysis(event["id"], json.dumps(analysis))

            high_events = [
                e for e in events
                if e.get("severity") in ("high", "critical") and not e.get("resolved")
            ]
            if len(high_events) >= 5:
                report = await generate_incident_report(high_events)
                await save_incident_report(report)
        except Exception as e:
            logger.error(f"[AI] Loop error: {e}")
        await asyncio.sleep(interval)