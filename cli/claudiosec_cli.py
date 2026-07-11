#!/usr/bin/env python3
"""
ClaudioSec CLI
Rich terminal interface for the security monitoring system
"""

import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich import print as rprint
from datetime import datetime
import httpx

console = Console()
API_BASE = os.getenv("CLAUDIOSEC_API", "http://localhost:8000")

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "bold yellow",
    "medium": "bold blue",
    "low": "green",
}


def get(endpoint: str) -> dict:
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(f"{API_BASE}{endpoint}")
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        console.print("[red]❌ Cannot connect to ClaudioSec API. Is it running?[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def post(endpoint: str, data: dict) -> dict:
    try:
        with httpx.Client(timeout=30) as client:
            r = client.post(f"{API_BASE}{endpoint}", json=data)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@click.group()
def cli():
    """🛡️  ClaudioSec — AI Security Monitoring System"""
    pass


@cli.command()
def status():
    """Show system status and stats"""
    data = get("/api/stats")
    sys_data = get("/api/system/stats")

    console.print(Panel.fit(
        "[bold cyan]🛡️  ClaudioSec Security Monitor[/bold cyan]\n[green]● System Operational[/green]",
        border_style="cyan"
    ))

    # Event stats
    table = Table(title="Security Events", border_style="dim")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total Events", str(data.get("total_events", 0)))
    table.add_row("Last 24 Hours", str(data.get("last_24h", 0)))
    table.add_row("[yellow]Unresolved[/yellow]", str(data.get("unresolved", 0)))
    table.add_row("[red]Critical Unresolved[/red]", str(data.get("critical_unresolved", 0)))

    by_sev = data.get("by_severity", {})
    for sev, count in by_sev.items():
        style = SEVERITY_STYLE.get(sev, "white")
        table.add_row(f"[{style}]{sev.title()}[/{style}]", str(count))

    console.print(table)

    # System stats
    sys_table = Table(title="System Resources", border_style="dim")
    sys_table.add_column("Resource", style="cyan")
    sys_table.add_column("Usage", justify="right")
    sys_table.add_row("CPU", f"{sys_data.get('cpu_percent', 0):.1f}%")
    sys_table.add_row("Memory", f"{sys_data.get('memory', {}).get('percent', 0):.1f}%")
    sys_table.add_row("Disk", f"{sys_data.get('disk', {}).get('percent', 0):.1f}%")
    sys_table.add_row("Connections", str(sys_data.get("connections", 0)))
    sys_table.add_row("Processes", str(sys_data.get("processes", 0)))
    console.print(sys_table)


@cli.command()
@click.option("--limit", "-n", default=20, help="Number of events to show")
@click.option("--severity", "-s", default=None, help="Filter by severity: low/medium/high/critical")
@click.option("--module", "-m", default=None, help="Filter by module")
@click.option("--unresolved", "-u", is_flag=True, help="Show only unresolved")
def events(limit, severity, module, unresolved):
    """List security events"""
    params = f"?limit={limit}"
    if severity:
        params += f"&severity={severity}"
    if module:
        params += f"&source_module={module}"
    if unresolved:
        params += "&resolved=false"

    data = get(f"/api/events{params}")
    events_list = data.get("events", [])

    if not events_list:
        console.print("[yellow]No events found.[/yellow]")
        return

    table = Table(title=f"Security Events ({len(events_list)})", border_style="dim", show_lines=True)
    table.add_column("ID", style="dim", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=45)
    table.add_column("Module", width=18)
    table.add_column("Time", width=20)
    table.add_column("AI", width=4)

    for e in events_list:
        sev = e.get("severity", "low")
        style = SEVERITY_STYLE.get(sev, "white")
        table.add_row(
            str(e.get("id", "")),
            f"[{style}]{sev.upper()}[/{style}]",
            e.get("title", "")[:45],
            e.get("source_module", ""),
            (e.get("timestamp", "")[:19] or "").replace("T", " "),
            "✓" if e.get("ai_analyzed") else "·",
        )

    console.print(table)


@cli.command()
@click.argument("event_id", type=int)
def inspect(event_id):
    """Inspect a specific event in detail"""
    data = get(f"/api/events/{event_id}")
    sev = data.get("severity", "low")
    style = SEVERITY_STYLE.get(sev, "white")

    console.print(Panel(
        f"[{style}]{sev.upper()}[/{style}]  {data.get('title', '')}",
        title=f"Event #{event_id}",
        border_style=sev if sev != "medium" else "blue",
    ))

    info = Table.grid(padding=(0, 2))
    info.add_column(style="cyan")
    info.add_column()
    info.add_row("Type:", data.get("event_type", ""))
    info.add_row("Module:", data.get("source_module", ""))
    info.add_row("Time:", data.get("timestamp", "")[:19].replace("T", " ") + " UTC")
    if data.get("source_ip"):
        info.add_row("Source IP:", data.get("source_ip"))
    if data.get("username"):
        info.add_row("Username:", data.get("username"))
    if data.get("file_path"):
        info.add_row("File:", data.get("file_path"))
    info.add_row("Resolved:", "Yes ✓" if data.get("resolved") else "No")
    console.print(info)

    console.print(Panel(data.get("description", ""), title="Description", border_style="dim"))

    if data.get("ai_analysis"):
        try:
            analysis = json.loads(data["ai_analysis"])
            ai_text = "\n".join([
                f"[cyan]Threat Type:[/cyan] {analysis.get('threat_type', '?')}",
                f"[cyan]Confidence:[/cyan] {analysis.get('confidence', 0)}%",
                f"[cyan]False Positive Risk:[/cyan] {analysis.get('false_positive_likelihood', '?')}",
                f"\n[cyan]Summary:[/cyan] {analysis.get('summary', '')}",
                f"\n[cyan]Immediate Action:[/cyan] [yellow]{analysis.get('immediate_action', '')}[/yellow]",
                f"\n[cyan]Remediation:[/cyan]",
            ] + [f"  {i+1}. {step}" for i, step in enumerate(analysis.get("remediation", []))])
            console.print(Panel(ai_text, title="🤖 AI Analysis", border_style="green"))
        except Exception:
            console.print(Panel(data["ai_analysis"][:500], title="🤖 AI Analysis", border_style="green"))


@cli.command()
@click.argument("event_id", type=int)
def analyze(event_id):
    """Trigger AI analysis on a specific event"""
    with console.status(f"[cyan]Running AI analysis on event #{event_id}...[/cyan]"):
        data = post(f"/api/events/{event_id}/analyze", {})

    analysis = data.get("analysis", {})
    console.print(Panel(
        "\n".join([
            f"[cyan]Threat:[/cyan] {analysis.get('threat_type', '?')} (confidence: {analysis.get('confidence', 0)}%)",
            f"[cyan]Threat Level:[/cyan] {analysis.get('threat_level', '?')}",
            f"[cyan]False Positive Risk:[/cyan] {analysis.get('false_positive_likelihood', '?')}",
            f"\n[yellow]{analysis.get('summary', '')}[/yellow]",
            f"\n[red]Immediate Action: {analysis.get('immediate_action', '')}[/red]",
            "\nRemediation:",
        ] + [f"  {i+1}. {s}" for i, s in enumerate(analysis.get("remediation", []))]),
        title=f"🤖 AI Analysis — Event #{event_id}",
        border_style="green",
    ))


@cli.command()
@click.argument("event_id", type=int)
def resolve(event_id):
    """Mark an event as resolved"""
    post(f"/api/events/{event_id}/resolve", {})
    console.print(f"[green]✓ Event #{event_id} marked as resolved[/green]")


@cli.command()
def report():
    """Generate an AI incident report from unresolved events"""
    with console.status("[cyan]Generating incident report...[/cyan]"):
        data = post("/api/reports/generate", {})

    r = data.get("report", {})
    console.print(Panel(
        "\n".join([
            f"[red]Severity: {r.get('severity', '?').upper()}[/red]",
            f"\n{r.get('threat_summary', '')}",
            f"\n[cyan]Attack Vector:[/cyan] {r.get('attack_vector', '?')}",
            f"\n[cyan]Remediation:[/cyan]\n{r.get('remediation_steps', '')}",
        ]),
        title=f"📋 Incident Report #{data.get('report_id')} — {r.get('title', '')}",
        border_style="red",
    ))


@cli.command()
def chat():
    """Interactive chat with the AI security analyst"""
    console.print(Panel(
        "[green]ClaudioSec AI Analyst ready.[/green]\nAsk me anything about your security posture.\nType [cyan]exit[/cyan] to quit.",
        title="🤖 AI Security Analyst",
        border_style="green",
    ))

    history = []
    while True:
        try:
            user_input = console.input("[cyan]You:[/cyan] ").strip()
            if user_input.lower() in ("exit", "quit", "q"):
                break
            if not user_input:
                continue

            history.append({"role": "user", "content": user_input})

            with console.status("[dim]AI thinking...[/dim]"):
                data = post("/api/chat", {"messages": history})

            response = data.get("response", "No response")
            history.append({"role": "assistant", "content": response})
            console.print(Panel(response, title="🤖 ClaudioSec AI", border_style="green"))

        except KeyboardInterrupt:
            break

    console.print("[dim]Analyst session ended.[/dim]")


@cli.command()
@click.argument("ip")
@click.option("--type", "-t", "threat_type", default="malicious", help="Threat type")
@click.option("--confidence", "-c", default=80, help="Confidence score 0-100")
def block_ip(ip, threat_type, confidence):
    """Add an IP to the threat intelligence database"""
    post("/api/threat-intel/ip", {
        "ip": ip,
        "threat_type": threat_type,
        "confidence": confidence,
        "source": "cli_manual",
    })
    console.print(f"[red]🚫 IP {ip} added to threat intel as '{threat_type}'[/red]")


if __name__ == "__main__":
    cli()