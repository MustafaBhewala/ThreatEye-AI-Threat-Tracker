# ThreatEye Development Guide

## Project Structure

```
ThreatEye/
├── frontend/              # React + Vite dashboard
│   ├── src/
│   ├── public/
│   └── package.json
│
├── src/                   # Python backend
│   ├── api/              # FastAPI endpoints
│   ├── collectors/       # Feed ingestion (VT, AbuseIPDB, OTX)
│   ├── enrichment/       # WHOIS, GeoIP, ASN services
│   ├── ml_engine/        # ML models & scoring
│   └── storage/          # Database layer (SQLAlchemy)
│
├── config/               # Configuration files
│   ├── config.example.json
│   └── (config.json - created from example)
│
├── data/                 # Data storage
│   ├── threateye.db     # SQLite database
│   └── reports/         # Generated reports
│
├── models/              # Trained ML models
│   ├── risk_classifier.pkl
│   └── anomaly_detector.pkl
│
├── tests/               # Unit & integration tests
└── docs/                # Additional documentation
```

## Setup Steps

### 1. Backend Setup (Python)

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
copy .env.example .env
copy config\config.example.json config\config.json
# Edit .env and config.json with your API keys
```

### 2. Frontend Setup (React)

```bash
cd frontend
npm create vite@latest . -- --template react
npm install
npm install axios recharts react-router-dom @tanstack/react-query
npm run dev
```

### 3. Get API Keys (Free Tiers)

#### VirusTotal
1. Visit: https://www.virustotal.com/gui/join-us
2. Create account
3. Go to API Key section
4. Copy API key (4 req/min, 500/day)

#### AbuseIPDB
1. Visit: https://www.abuseipdb.com/register
2. Create account
3. Get API key from account settings
4. Free: 1,000 requests/day

#### AlienVault OTX
1. Visit: https://otx.alienvault.com/
2. Create account
3. Get API key from settings
4. Free: Unlimited requests

## Development Workflow

### Phase 1: Core Infrastructure ✅
- [x] Repository setup
- [x] Folder structure
- [x] Configuration files
- [ ] Database schema design
- [ ] Base API setup

### Phase 2: Data Collection
- [ ] VirusTotal collector
- [ ] AbuseIPDB collector
- [ ] OTX collector
- [ ] Data normalization

### Phase 3: Enrichment
- [ ] WHOIS lookup
- [ ] GeoIP integration
- [ ] ASN resolution
- [ ] Domain age calculation

### Phase 4: ML Engine
- [ ] Feature engineering
- [ ] Risk classifier training
- [ ] Anomaly detector
- [ ] Scoring algorithm

### Phase 5: API Development
- [ ] CRUD endpoints
- [ ] Search & filter
- [ ] Real-time updates
- [ ] Authentication

### Phase 6: Frontend
- [ ] Dashboard layout
- [ ] Live threat table
- [ ] Detail drill-down
- [ ] Visualization charts
- [ ] Alert configuration

### Phase 7: Alerts & Reports
- [ ] Email notifications
- [ ] Slack integration
- [ ] CSV export
- [ ] PDF reports

### Phase 8: Testing & Polish
- [ ] Unit tests
- [ ] Integration tests
- [ ] Performance optimization
- [ ] Documentation

## Running the Application

### Backend
```bash
# From project root
uvicorn src.api.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm run dev
```

### Access
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## Tech Stack Details

### Backend
- **FastAPI**: Modern async web framework
- **SQLAlchemy**: ORM for database operations
- **Pydantic**: Data validation
- **scikit-learn**: ML models
- **APScheduler**: Background jobs

### Frontend
- **React 18**: UI framework
- **Vite**: Build tool
- **Recharts**: Data visualization
- **React Query**: Data fetching
- **React Router**: Navigation

### APIs Used
- **VirusTotal API v3**: File/URL/IP reputation
- **AbuseIPDB API v2**: IP abuse reports
- **AlienVault OTX**: Threat pulse data
- **python-whois**: Domain WHOIS
- **GeoIP2**: IP geolocation

## Next Steps

1. **Configure API Keys**: Add your keys to `.env` and `config/config.json`
2. **Design Database Schema**: Define tables for threats, indicators, alerts
3. **Build Feed Collectors**: Start with one API (recommend OTX - unlimited free)
4. **Create FastAPI Skeleton**: Basic endpoints structure
5. **Initialize React App**: Set up frontend with routing

---

**Ready to start building? Let's move to the next phase! 🚀**
