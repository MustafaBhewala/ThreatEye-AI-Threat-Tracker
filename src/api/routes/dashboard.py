"""
Dashboard API Router
Endpoints for dashboard statistics and metrics
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.storage.database import get_db
from src.storage.models import (
    ThreatIndicator, Alert, ScanJob, FeedData,
    RiskLevel, IndicatorType, ThreatCategory
)
from src.api.schemas import DashboardStatsResponse

router = APIRouter()


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Get comprehensive dashboard statistics
    """
    # Total indicators
    total_indicators = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True
    ).count()
    
    # Malicious vs Safe counts
    malicious_count = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True
    ).count()
    
    safe_count = total_indicators - malicious_count
    
    # Count by risk level
    critical_count = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.risk_level == RiskLevel.CRITICAL
    ).count()
    
    high_count = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.risk_level == RiskLevel.HIGH
    ).count()
    
    medium_count = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.risk_level == RiskLevel.MEDIUM
    ).count()
    
    low_count = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.risk_level == RiskLevel.LOW
    ).count()
    
    # Alert counts
    active_alerts = db.query(Alert).filter(
        Alert.is_resolved == False
    ).count()
    
    total_alerts = db.query(Alert).count()
    
    # Last scan time
    last_scan = db.query(ScanJob.completed_at).order_by(
        desc(ScanJob.completed_at)
    ).first()
    
    return {
        "total_indicators": total_indicators,
        "malicious_count": malicious_count,
        "safe_count": safe_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "active_alerts": active_alerts,
        "total_alerts": total_alerts,
        "last_scan": last_scan[0] if last_scan else None
    }


@router.get("/recent-threats")
async def get_recent_threats(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get most recent threat indicators
    """
    threats = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True
    ).order_by(desc(ThreatIndicator.last_seen)).limit(limit).all()
    
    return [
        {
            "id": t.id,
            "indicator_type": t.indicator_type.value,
            "indicator_value": t.indicator_value,
            "threat_score": t.threat_score,
            "risk_level": t.risk_level.value,
            "primary_category": t.primary_category.value,
            "last_seen": t.last_seen
        }
        for t in threats
    ]


@router.get("/threat-timeline")
async def get_threat_timeline(
    days: int = 7,
    db: Session = Depends(get_db)
):
    """
    Get threat count timeline for the last N days
    """
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Query threats grouped by date
    timeline = db.query(
        func.date(ThreatIndicator.last_seen).label('date'),
        func.count(ThreatIndicator.id).label('count')
    ).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.last_seen >= start_date
    ).group_by(
        func.date(ThreatIndicator.last_seen)
    ).order_by('date').all()
    
    return [
        {
            "date": str(row.date),
            "count": row.count
        }
        for row in timeline
    ]


@router.get("/risk-distribution")
async def get_risk_distribution(db: Session = Depends(get_db)):
    """
    Get distribution of threats by risk level
    """
    distribution = db.query(
        ThreatIndicator.risk_level,
        func.count(ThreatIndicator.id).label('count')
    ).filter(
        ThreatIndicator.is_active == True
    ).group_by(ThreatIndicator.risk_level).all()
    
    return [
        {
            "risk_level": row.risk_level.value,
            "count": row.count
        }
        for row in distribution
    ]


@router.get("/threat-categories")
async def get_threat_categories(db: Session = Depends(get_db)):
    """
    Get distribution of threats by category
    """
    categories = db.query(
        ThreatIndicator.primary_category,
        func.count(ThreatIndicator.id).label('count')
    ).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True
    ).group_by(ThreatIndicator.primary_category).all()
    
    return [
        {
            "category": row.primary_category.value,
            "count": row.count
        }
        for row in categories
    ]


@router.get("/geographic-distribution")
async def get_geographic_distribution(db: Session = Depends(get_db)):
    """
    Get distribution of threats by country
    """
    from src.storage.models import EnrichmentData
    
    geo_dist = db.query(
        EnrichmentData.geo_country,
        EnrichmentData.geo_country_code,
        func.count(EnrichmentData.id).label('count')
    ).join(
        ThreatIndicator,
        EnrichmentData.indicator_id == ThreatIndicator.id
    ).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True,
        EnrichmentData.geo_country.isnot(None)
    ).group_by(
        EnrichmentData.geo_country,
        EnrichmentData.geo_country_code
    ).order_by(desc('count')).limit(10).all()
    
    return [
        {
            "country": row.geo_country,
            "country_code": row.geo_country_code,
            "count": row.count
        }
        for row in geo_dist
    ]


@router.get("/top-asns")
async def get_top_asns(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get top ASNs with most malicious indicators
    """
    from src.storage.models import EnrichmentData
    
    top_asns = db.query(
        EnrichmentData.asn_number,
        EnrichmentData.asn_name,
        EnrichmentData.asn_organization,
        func.count(EnrichmentData.id).label('count')
    ).join(
        ThreatIndicator,
        EnrichmentData.indicator_id == ThreatIndicator.id
    ).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True,
        EnrichmentData.asn_number.isnot(None)
    ).group_by(
        EnrichmentData.asn_number,
        EnrichmentData.asn_name,
        EnrichmentData.asn_organization
    ).order_by(desc('count')).limit(limit).all()
    
    return [
        {
            "asn_number": row.asn_number,
            "asn_name": row.asn_name,
            "asn_organization": row.asn_organization,
            "threat_count": row.count
        }
        for row in top_asns
    ]


@router.get("/recent-alerts")
async def get_recent_alerts(
    limit: int = 5,
    db: Session = Depends(get_db)
):
    """
    Get most recent unresolved alerts
    """
    alerts = db.query(Alert).filter(
        Alert.is_resolved == False
    ).order_by(desc(Alert.created_at)).limit(limit).all()
    
    return [
        {
            "id": alert.id,
            "indicator_id": alert.indicator_id,
            "severity": alert.severity.value,
            "title": alert.title,
            "description": alert.description,
            "is_acknowledged": alert.is_acknowledged,
            "created_at": alert.created_at
        }
        for alert in alerts
    ]


@router.get("/recently-analyzed")
async def get_recently_analyzed(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get recently analyzed/checked threat indicators (based on last_analyzed timestamp)
    Shows threats that were recently looked up or scanned
    """
    threats = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True,
        ThreatIndicator.last_analyzed.isnot(None)
    ).order_by(desc(ThreatIndicator.last_analyzed)).limit(limit).all()
    
    return [
        {
            "id": t.id,
            "indicator_type": t.indicator_type.value,
            "indicator_value": t.indicator_value,
            "threat_score": t.threat_score,
            "risk_level": t.risk_level.value,
            "primary_category": t.primary_category.value,
            "confidence_level": t.confidence_level.value,
            "last_analyzed": t.last_analyzed,
            "last_seen": t.last_seen
        }
        for t in threats
    ]


@router.get("/threat-trends")
async def get_threat_trends(
    days: int = 7,
    db: Session = Depends(get_db)
):
    """
    Get detailed threat trends with malicious vs total breakdown
    """
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Generate all dates in range
    date_range = []
    current_date = start_date
    while current_date <= end_date:
        date_range.append(current_date.date())
        current_date += timedelta(days=1)
    
    # Get total threats per day
    total_threats = db.query(
        func.date(ThreatIndicator.last_seen).label('date'),
        func.count(ThreatIndicator.id).label('count')
    ).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.last_seen >= start_date
    ).group_by(
        func.date(ThreatIndicator.last_seen)
    ).all()
    
    # Get malicious threats per day
    malicious_threats = db.query(
        func.date(ThreatIndicator.last_seen).label('date'),
        func.count(ThreatIndicator.id).label('count')
    ).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True,
        ThreatIndicator.last_seen >= start_date
    ).group_by(
        func.date(ThreatIndicator.last_seen)
    ).all()
    
    # Create lookup dictionaries
    total_dict = {str(row.date): row.count for row in total_threats}
    malicious_dict = {str(row.date): row.count for row in malicious_threats}
    
    # Build result with all dates
    result = []
    for date in date_range:
        date_str = str(date)
        result.append({
            "date": date.strftime("%b %d"),
            "threats": total_dict.get(date_str, 0),
            "malicious": malicious_dict.get(date_str, 0)
        })
    
    return result


@router.get("/top-malicious-ips")
async def get_top_malicious_ips(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get top malicious IP addresses by threat score
    """
    ips = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True,
        ThreatIndicator.indicator_type == IndicatorType.IP
    ).order_by(desc(ThreatIndicator.threat_score)).limit(limit).all()
    
    return [
        {
            "id": ip.id,
            "indicator_value": ip.indicator_value,
            "threat_score": ip.threat_score,
            "risk_level": ip.risk_level.value,
            "primary_category": ip.primary_category.value,
            "confidence_level": ip.confidence_level.value,
            "last_seen": ip.last_seen,
            "feed_hits": ip.feed_hits
        }
        for ip in ips
    ]


@router.get("/top-malicious-domains")
async def get_top_malicious_domains(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get top malicious domains by threat score
    """
    domains = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True,
        ThreatIndicator.indicator_type == IndicatorType.DOMAIN
    ).order_by(desc(ThreatIndicator.threat_score)).limit(limit).all()
    
    return [
        {
            "id": domain.id,
            "indicator_value": domain.indicator_value,
            "threat_score": domain.threat_score,
            "risk_level": domain.risk_level.value,
            "primary_category": domain.primary_category.value,
            "confidence_level": domain.confidence_level.value,
            "last_seen": domain.last_seen,
            "feed_hits": domain.feed_hits
        }
        for domain in domains
    ]


@router.get("/live-stats")
async def get_live_stats(db: Session = Depends(get_db)):
    """
    Get real-time statistics for live dashboard updates
    Includes counts updated in last 24 hours
    """
    last_24h = datetime.utcnow() - timedelta(hours=24)
    
    # Threats detected in last 24 hours
    new_threats_24h = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.first_seen >= last_24h
    ).count()
    
    # Malicious detected in last 24 hours
    new_malicious_24h = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True,
        ThreatIndicator.first_seen >= last_24h
    ).count()
    
    # Critical threats in last 24 hours
    new_critical_24h = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.risk_level == RiskLevel.CRITICAL,
        ThreatIndicator.first_seen >= last_24h
    ).count()
    
    # Scans in last hour
    last_hour = datetime.utcnow() - timedelta(hours=1)
    scans_last_hour = db.query(ThreatIndicator).filter(
        ThreatIndicator.last_analyzed >= last_hour
    ).count()
    
    return {
        "new_threats_24h": new_threats_24h,
        "new_malicious_24h": new_malicious_24h,
        "new_critical_24h": new_critical_24h,
        "scans_last_hour": scans_last_hour,
        "timestamp": datetime.utcnow().isoformat()
    }
