# 🛡️ ClaudioSec — AI-Powered Security Monitoring System

> Full-stack security monitoring powered by Claude AI. Real-time threat detection, anomaly analysis, incident reporting, and remediation — all in one system.

---

## 🚀 Features

| Module | Description |
|---|---|
| 🌐 Network Monitor | Packet sniffing, port scan detection, suspicious traffic |
| 📋 Log Analyzer | System/app log ingestion, anomaly detection |
| 🗂️ File Integrity | SHA256 hash tracking, tamper detection |
| 🔐 Auth Monitor | Failed logins, SSH brute force, sudo abuse |
| ⚙️ Process Monitor | Suspicious processes, privilege escalation |
| 🌍 DNS Monitor | DNS anomaly detection, exfiltration detection |
| 🤖 Claude AI Brain | Real-time threat analysis, incident reports, remediation |
| 📊 Web Dashboard | FastAPI + React live dashboard |
| 🔔 Alerts | Slack + Webhook notifications |
| 💻 CLI | Full CLI interface |

---

## 🏗️ Stack

- **Backend:** Python 3.12, FastAPI, SQLite
- **Monitoring:** Scapy, watchdog, psutil, pyinotify
- **AI:** Anthropic Claude API
- **Frontend:** React + Tailwind CSS
- **Alerts:** Slack Webhooks, generic webhooks
- **Infra:** Docker Compose

---

## ⚡ Quick Start

```bash
# Clone and setup
cp .env.example .env
# Add your ANTHROPIC_API_KEY and SLACK_WEBHOOK_URL to .env

# Docker (recommended)
docker-compose up --build

# Manual
pip install -r requirements.txt
python -m claudiosec.main
```

## 🌐 Access

- Dashboard: http://localhost:8000
- API Docs: http://localhost:8000/docs
- CLI: `python cli/claudiosec_cli.py --help`

---

## 📁 Project Structure

```
claudiosec/
├── core/           # Core engine, DB, event bus
├── monitors/       # All monitoring modules
├── api/            # FastAPI routes
├── alerts/         # Slack + webhook alerting
├── frontend/       # React dashboard
├── cli/            # CLI interface
├── tests/          # pytest suite
└── docker/         # Docker configs
```