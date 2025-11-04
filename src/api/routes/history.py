"""
Scan History API Router
Tracks and retrieves scan history for all indicators
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from datetime import datetime, timedelta
from typing import Optional, List
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.storage.database import get_db
from src.storage.models import ThreatIndicator, IndicatorType, RiskLevel

router = APIRouter()


@router.get("/recent")
async def get_recent_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    risk_level: Optional[str] = None,
    indicator_type: Optional[str] = None,
    days: Optional[int] = Query(7, ge=1, le=365),
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Get recent scan history with filters
    
    Args:
        page: Page number
        page_size: Items per page
        risk_level: Filter by risk level (safe, low, medium, high, critical)
        indicator_type: Filter by type (ip, domain, url)
        days: History range in days (default 7)
        search: Search in indicator value
    """
    
    # Base query - only include indicators that were analyzed
    query = db.query(ThreatIndicator).filter(
        ThreatIndicator.last_analyzed.isnot(None)
    )
    
    # Date filter
    since_date = datetime.utcnow() - timedelta(days=days)
    query = query.filter(ThreatIndicator.last_analyzed >= since_date)
    
    # Risk level filter
    if risk_level:
        try:
            risk_enum = RiskLevel[risk_level.upper()]
            query = query.filter(ThreatIndicator.risk_level == risk_enum)
        except KeyError:
            pass
    
    # Indicator type filter
    if indicator_type:
        try:
            type_enum = IndicatorType[indicator_type.upper()]
            query = query.filter(ThreatIndicator.indicator_type == type_enum)
        except KeyError:
            pass
    
    # Search filter
    if search:
        query = query.filter(
            ThreatIndicator.indicator_value.contains(search)
        )
    
    # Count total
    total = query.count()
    
    # Order by most recently analyzed
    query = query.order_by(desc(ThreatIndicator.last_analyzed))
    
    # Pagination
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()
    
    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'pages': (total + page_size - 1) // page_size,
        'items': items
    }


@router.get("/stats")
async def get_history_stats(
    days: int = Query(7, ge=1, le=365),
    db: Session = Depends(get_db)
):
    """
    Get statistics for scan history
    
    Args:
        days: Statistics range in days
    """
    
    since_date = datetime.utcnow() - timedelta(days=days)
    
    # Total scans
    total_scans = db.query(ThreatIndicator).filter(
        ThreatIndicator.last_analyzed >= since_date,
        ThreatIndicator.last_analyzed.isnot(None)
    ).count()
    
    # Malicious count
    malicious_count = db.query(ThreatIndicator).filter(
        ThreatIndicator.last_analyzed >= since_date,
        ThreatIndicator.is_malicious == True
    ).count()
    
    # By risk level
    risk_breakdown = {}
    for risk in RiskLevel:
        count = db.query(ThreatIndicator).filter(
            ThreatIndicator.last_analyzed >= since_date,
            ThreatIndicator.risk_level == risk
        ).count()
        risk_breakdown[risk.value] = count
    
    # By indicator type
    type_breakdown = {}
    for ind_type in IndicatorType:
        count = db.query(ThreatIndicator).filter(
            ThreatIndicator.last_analyzed >= since_date,
            ThreatIndicator.indicator_type == ind_type
        ).count()
        type_breakdown[ind_type.value] = count
    
    # Recent activity (last 24 hours by hour)
    recent_activity = []
    for hour in range(24):
        hour_start = datetime.utcnow() - timedelta(hours=hour+1)
        hour_end = datetime.utcnow() - timedelta(hours=hour)
        
        count = db.query(ThreatIndicator).filter(
            ThreatIndicator.last_analyzed >= hour_start,
            ThreatIndicator.last_analyzed < hour_end
        ).count()
        
        recent_activity.append({
            'hour': hour_start.strftime('%Y-%m-%d %H:00'),
            'count': count
        })
    
    return {
        'total_scans': total_scans,
        'malicious_count': malicious_count,
        'clean_count': total_scans - malicious_count,
        'risk_breakdown': risk_breakdown,
        'type_breakdown': type_breakdown,
        'recent_activity': list(reversed(recent_activity))
    }


@router.delete("/{indicator_id}")
async def delete_history_item(
    indicator_id: int,
    db: Session = Depends(get_db)
):
    """Delete a history item"""
    
    indicator = db.query(ThreatIndicator).filter(
        ThreatIndicator.id == indicator_id
    ).first()
    
    if not indicator:
        return {'success': False, 'message': 'Item not found'}
    
    db.delete(indicator)
    db.commit()
    
    return {'success': True, 'message': 'History item deleted'}


@router.delete("/clear")
async def clear_history(
    days: Optional[int] = Query(None, ge=1),
    db: Session = Depends(get_db)
):
    """
    Clear scan history
    
    Args:
        days: Clear items older than N days (if not specified, clears all)
    """
    
    query = db.query(ThreatIndicator)
    
    if days:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(ThreatIndicator.last_analyzed < cutoff_date)
    
    count = query.count()
    query.delete()
    db.commit()
    
    return {
        'success': True,
        'message': f'Cleared {count} history items'
    }
