# ThreatEye Database Schema Documentation

## Overview
Secure, well-organized relational database schema for ThreatEye threat intelligence platform.

## Database Design Principles

### 🔒 Security Features
- **Foreign Key Constraints**: Enforced referential integrity
- **Indexes**: Optimized query performance on frequently searched columns
- **Audit Logging**: User activity tracking for compliance
- **Cascading Deletes**: Automatic cleanup of related records
- **WAL Mode**: Write-Ahead Logging for SQLite concurrency
- **Connection Pooling**: Efficient resource management

### 📊 Data Organization
- **Normalized Structure**: Minimal data redundancy
- **Enum Types**: Consistent categorical data
- **JSON Fields**: Flexible structured data storage
- **Timestamp Tracking**: Created/updated timestamps on all tables
- **Soft Deletes**: `is_active` flags preserve historical data

---

## Core Tables

### 1. **threat_indicators** (Main Table)
Stores all threat indicators (IPs, Domains, URLs) with risk assessments.

**Key Fields:**
- `indicator_type`: IP, Domain, or URL
- `indicator_value`: The actual IP/domain/URL
- `threat_score`: 0-100 risk score
- `risk_level`: SAFE, LOW, MEDIUM, HIGH, CRITICAL
- `is_malicious`: Boolean flag
- `primary_category`: Main threat type (malware, phishing, etc.)
- `feed_hits`: Number of feeds that flagged this indicator
- `first_seen` / `last_seen`: Temporal tracking

**Relationships:**
- One-to-Many: `feed_data`, `ml_predictions`, `alerts`
- One-to-One: `enrichment_data`

**Indexes:**
- Primary: `id`
- Unique: (`indicator_type`, `indicator_value`)
- Performance: `threat_score`, `risk_level`, `is_malicious`, `last_seen`

---

### 2. **feed_data**
Raw data from threat intelligence feeds (VirusTotal, AbuseIPDB, OTX).

**Purpose:**
- Store original API responses for audit
- Cross-validate threats across multiple sources
- Track feed reliability

**Key Fields:**
- `feed_source`: Which API (VirusTotal/AbuseIPDB/OTX)
- `is_malicious`: Feed's determination
- `reputation_score`: Feed's own score
- `detection_count`: e.g., 45/70 engines for VirusTotal
- `raw_response`: Complete JSON response

**Why Important:**
- Enables cross-feed correlation
- Provides evidence trail for alerts
- Allows feed performance comparison

---

### 3. **enrichment_data**
Contextual information (WHOIS, GeoIP, ASN) for each indicator.

**WHOIS Data:**
- Domain registrar, creation/expiration dates
- Domain age (suspicious if < 30 days)
- Registrant information

**GeoIP Data:**
- Country, city, region
- Latitude/longitude for mapping
- Timezone

**ASN Data:**
- AS Number and Name
- Organization (e.g., "GOOGLE", "Bulletproof Hosting")
- ISP information
- Network range

**Why Important:**
- Young domains = likely phishing
- Certain countries = higher risk
- Bulletproof hosting ASNs = malicious infrastructure

---

### 4. **ml_predictions**
Machine learning model predictions and anomaly detection results.

**Key Fields:**
- `model_name` / `model_version`: Track which model
- `predicted_class`: safe/suspicious/malicious
- `confidence`: 0-1 prediction confidence
- `probability_*`: Individual class probabilities
- `is_anomaly`: Anomaly detector flag
- `anomaly_score`: How unusual the indicator is
- `feature_importance`: Top features that influenced prediction

**Why Important:**
- ML predictions supplement feed data
- Anomaly detection finds zero-day threats
- Feature importance explains decisions (transparency)

---

## Alert & Monitoring Tables

### 5. **alerts**
Security alerts triggered by high-risk indicators.

**Key Fields:**
- `severity`: Risk level (HIGH/CRITICAL)
- `triggered_by`: What caused alert (threshold, anomaly, etc.)
- `is_acknowledged` / `is_resolved`: Status tracking
- `notification_sent`: Alert delivery status
- `notification_channels`: Email, Slack, etc.

**Workflow:**
1. Indicator exceeds threshold → Alert created
2. Notification sent to security team
3. Analyst acknowledges alert
4. Investigation completed → Mark resolved

---

### 6. **user_activity**
Audit log for compliance and security monitoring.

**Tracks:**
- User actions (search, alert acknowledge, config changes)
- IP addresses, endpoints, HTTP methods
- Timestamps for every action

**Use Cases:**
- Security audits
- Compliance reporting (SOC 2, ISO 27001)
- Troubleshooting user issues
- Detecting insider threats

---

### 7. **scan_jobs**
Background job tracking for scheduled operations.

**Job Types:**
- `feed_sync`: Collect data from APIs
- `enrichment`: WHOIS/GeoIP lookups
- `ml_scan`: Run ML models on new data

**Metrics:**
- Indicators processed
- New threats found
- Alerts triggered
- Duration and error tracking

---

## Configuration Tables

### 8. **reports**
Generated PDF/CSV reports metadata.

**Key Fields:**
- Report type (daily, weekly, custom)
- Time range, statistics
- File path and size
- Access control (public/private)

---

### 9. **system_config**
Application-wide settings.

**Examples:**
- Alert thresholds
- Feed sync intervals
- ML model versions
- Feature flags

---

## Database Relationships

```
threat_indicators (1) ←→ (N) feed_data
                  (1) ←→ (1) enrichment_data
                  (1) ←→ (N) ml_predictions
                  (1) ←→ (N) alerts
```

---

## Indexes & Performance

### Critical Indexes:
1. **Unique Constraint**: `(indicator_type, indicator_value)` - Prevents duplicates
2. **Composite Index**: `(threat_score, risk_level)` - Fast filtering by risk
3. **Time-Based**: `last_seen`, `created_at` - Efficient temporal queries
4. **Status Flags**: `is_malicious`, `is_active` - Quick status filters
5. **Foreign Keys**: All relationships indexed automatically

### Query Optimization:
- **Feed Correlation**: `SELECT * FROM feed_data WHERE indicator_id = ?` (indexed)
- **High-Risk Search**: `SELECT * FROM threat_indicators WHERE risk_level = 'CRITICAL'` (indexed)
- **Recent Threats**: `SELECT * FROM threat_indicators WHERE last_seen > ?` (indexed)

---

## Security Best Practices

### 1. **Parameterized Queries**
All queries use SQLAlchemy ORM to prevent SQL injection.

### 2. **Connection Pooling**
Reuses database connections for efficiency and security.

### 3. **Transaction Management**
All operations wrapped in transactions with automatic rollback on errors.

### 4. **Audit Trail**
Every action logged in `user_activity` table.

### 5. **Data Retention**
Soft deletes with `is_active` flag preserve historical data.

### 6. **Foreign Key Enforcement**
Cascading deletes maintain referential integrity.

---

## Sample Queries

### Get High-Risk Indicators with Enrichment:
```python
indicators = session.query(ThreatIndicator)\
    .join(EnrichmentData)\
    .filter(ThreatIndicator.risk_level == RiskLevel.HIGH)\
    .filter(ThreatIndicator.is_active == True)\
    .all()
```

### Cross-Feed Correlation:
```python
multi_feed_threats = session.query(ThreatIndicator)\
    .filter(ThreatIndicator.feed_hits >= 2)\
    .filter(ThreatIndicator.is_malicious == True)\
    .all()
```

### Recent Alerts by Severity:
```python
alerts = session.query(Alert)\
    .filter(Alert.is_resolved == False)\
    .filter(Alert.severity.in_([RiskLevel.HIGH, RiskLevel.CRITICAL]))\
    .order_by(Alert.created_at.desc())\
    .all()
```

---

## Database Initialization

### First Time Setup:
```bash
python init_database.py
# Choose option 1 or 3 (with sample data)
```

### Reset Database:
```bash
python init_database.py
# Choose option 2 (WARNING: Deletes all data)
```

### Check Statistics:
```bash
python init_database.py
# Choose option 4
```

---

## Production Considerations

### For Production Deployment:

1. **Switch to PostgreSQL/MySQL**:
   - Update `DATABASE_URL` in `.env`
   - Better concurrency and scalability

2. **Add Backup Strategy**:
   - Automated daily backups
   - Point-in-time recovery

3. **Implement Partitioning**:
   - Partition large tables by date
   - Archive old data

4. **Add Read Replicas**:
   - Separate read/write workloads
   - Improve query performance

5. **Enable SSL/TLS**:
   - Encrypt database connections
   - Use certificate authentication

---

## Next Steps

✅ Database schema designed and documented  
✅ Security features implemented  
✅ Sample data available for testing  

**Ready to build:**
- Feed collectors (use this database)
- FastAPI endpoints (query this database)
- ML engine (train on this data)
- Dashboard (visualize this data)
