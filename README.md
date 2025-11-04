# 🛡️ ThreatEye – AI-Powered Malicious IP & Domain Tracker

> **Hackathon Project**: Core Cybersecurity - Proactive Threat Intelligence System

## 📋 Overview

ThreatEye is an intelligent threat intelligence platform that continuously ingests data from multiple OSINT feeds, enriches threat indicators with contextual information, and uses AI/ML to predict and detect malicious IPs and domains before they cause harm.

### Key Features
- 🔄 **Real-time Feed Collection**: VirusTotal, AbuseIPDB, AlienVault OTX
- 🧠 **AI-Powered Risk Scoring**: ML classifier + anomaly detection
- 🌍 **Threat Enrichment**: WHOIS, GeoIP, ASN, domain age analysis
- 📊 **Interactive Dashboard**: React-based visualization with drill-downs
- 🚨 **Smart Alerts**: Threshold-based notifications (Email/Slack)
- 📈 **Automated Reports**: CSV/PDF exports with actionable insights

## 🏗️ Architecture

```
ThreatEye/
├── frontend/          # React + Vite dashboard
├── src/
│   ├── api/          # FastAPI REST endpoints
│   ├── collectors/   # Threat feed ingestion
│   ├── enrichment/   # WHOIS, GeoIP, ASN services
│   ├── ml_engine/    # AI risk scoring & anomaly detection
│   └── storage/      # SQLite database layer
├── config/           # API keys & configurations
├── data/             # SQLite database files
├── models/           # Trained ML models
├── tests/            # Unit & integration tests
└── docs/             # Documentation
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ (for React frontend)
- Git

### Backend Setup

1. **Clone & Navigate**
```bash
cd "ThreatEye – AI-Powered Malicious IP & Domain Tracker"
```

2. **Create Virtual Environment**
```bash
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure API Keys**
```bash
cp config/config.example.json config/config.json
# Edit config/config.json with your API keys
```

5. **Run Backend**
```bash
uvicorn src.api.main:app --reload
```

### Frontend Setup

1. **Navigate to Frontend**
```bash
cd frontend
```

2. **Install Dependencies**
```bash
npm install
```

3. **Run Development Server**
```bash
npm run dev
```

## 🔑 API Keys (Free Tiers)

### VirusTotal
- Sign up: https://www.virustotal.com/gui/join-us
- Free tier: 4 requests/min, 500 requests/day

### AbuseIPDB
- Sign up: https://www.abuseipdb.com/register
- Free tier: 1,000 requests/day

### AlienVault OTX
- Sign up: https://otx.alienvault.com/
- Free tier: Unlimited requests

## 📊 Tech Stack

- **Backend**: FastAPI (Python 3.11+)
- **Frontend**: React + Vite
- **Database**: SQLite + SQLAlchemy
- **ML**: scikit-learn
- **Visualization**: Chart.js, Recharts
- **Deployment**: Docker (optional)

## 🎯 Problem Statement

Traditional threat intelligence systems are reactive and rely on static blacklists. ThreatEye solves this by:
- ✅ Automating threat data collection from multiple sources
- ✅ Predicting unknown threats using AI/ML
- ✅ Providing real-time correlation and enrichment
- ✅ Enabling proactive defense through early detection

## 🛣️ Roadmap

- [x] Repository setup
- [ ] Feed collectors implementation
- [ ] Enrichment engine
- [ ] ML risk scoring model
- [ ] Database schema & ORM
- [ ] FastAPI REST endpoints
- [ ] React dashboard
- [ ] Alert system
- [ ] Report generation
- [ ] Testing & optimization

## 👥 Team

Hackathon Project - Core Cybersecurity Domain

## 📄 License

MIT License - Built for Educational/Hackathon purposes

---

**Built with ❤️ for Cybersecurity Hackathon 2025**
