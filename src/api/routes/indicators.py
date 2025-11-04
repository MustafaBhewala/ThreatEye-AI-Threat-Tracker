"""
Indicators API Router
Endpoints for managing threat indicators
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, func
from typing import List, Optional
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.storage.database import get_db
from src.storage.models import ThreatIndicator, EnrichmentData, RiskLevel, IndicatorType, ThreatCategory
from src.api.schemas import (
    ThreatIndicatorResponse,
    ThreatIndicatorDetailResponse,
    PaginatedResponse,
    EnrichmentDataResponse
)

router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def get_indicators(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    indicator_type: Optional[str] = Query(None, description="Filter by type (ip/domain/url)"),
    is_malicious: Optional[bool] = Query(None, description="Filter by malicious status"),
    search: Optional[str] = Query(None, description="Search indicator value"),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of threat indicators with optional filters
    """
    # Base query
    query = db.query(ThreatIndicator).filter(ThreatIndicator.is_active == True)
    
    # Apply filters
    if risk_level:
        try:
            query = query.filter(ThreatIndicator.risk_level == RiskLevel[risk_level.upper()])
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid risk level: {risk_level}")
    
    if indicator_type:
        try:
            query = query.filter(ThreatIndicator.indicator_type == IndicatorType[indicator_type.upper()])
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid indicator type: {indicator_type}")
    
    if is_malicious is not None:
        query = query.filter(ThreatIndicator.is_malicious == is_malicious)
    
    if search:
        query = query.filter(ThreatIndicator.indicator_value.contains(search))
    
    # Get total count
    total = query.count()
    
    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size
    
    # Get paginated results
    indicators = query.order_by(desc(ThreatIndicator.last_seen)).offset(offset).limit(page_size).all()
    
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "data": indicators
    }


@router.get("/{indicator_id}", response_model=ThreatIndicatorDetailResponse)
async def get_indicator_by_id(
    indicator_id: int,
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific threat indicator
    """
    indicator = db.query(ThreatIndicator).filter(
        ThreatIndicator.id == indicator_id,
        ThreatIndicator.is_active == True
    ).first()
    
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    
    # Get enrichment data
    enrichment = db.query(EnrichmentData).filter(
        EnrichmentData.indicator_id == indicator_id
    ).first()
    
    # Convert to response model
    response = ThreatIndicatorDetailResponse.model_validate(indicator)
    if enrichment:
        response.enrichment = EnrichmentDataResponse.model_validate(enrichment)
    
    return response


@router.get("/search/{indicator_value}", response_model=Optional[ThreatIndicatorDetailResponse])
async def search_indicator(
    indicator_value: str,
    db: Session = Depends(get_db)
):
    """
    Search for a specific indicator by its value (IP/Domain/URL)
    Updates last_analyzed timestamp to track recent lookups
    """
    indicator = db.query(ThreatIndicator).filter(
        ThreatIndicator.indicator_value == indicator_value,
        ThreatIndicator.is_active == True
    ).first()
    
    if not indicator:
        return None
    
    # Update last_analyzed timestamp to track this lookup
    indicator.last_analyzed = datetime.utcnow()
    db.commit()
    
    # Get enrichment data
    enrichment = db.query(EnrichmentData).filter(
        EnrichmentData.indicator_id == indicator.id
    ).first()
    
    # Convert to response model
    response = ThreatIndicatorDetailResponse.model_validate(indicator)
    if enrichment:
        response.enrichment = EnrichmentDataResponse.model_validate(enrichment)
    
    return response


@router.get("/stats/summary")
async def get_indicators_summary(db: Session = Depends(get_db)):
    """
    Get summary statistics of all indicators
    """
    total = db.query(ThreatIndicator).filter(ThreatIndicator.is_active == True).count()
    malicious = db.query(ThreatIndicator).filter(
        ThreatIndicator.is_active == True,
        ThreatIndicator.is_malicious == True
    ).count()
    
    # Count by risk level
    risk_counts = db.query(
        ThreatIndicator.risk_level,
        func.count(ThreatIndicator.id)
    ).filter(ThreatIndicator.is_active == True).group_by(ThreatIndicator.risk_level).all()
    
    risk_dict = {level.value: 0 for level in RiskLevel}
    for level, count in risk_counts:
        risk_dict[level.value] = count
    
    # Count by type
    type_counts = db.query(
        ThreatIndicator.indicator_type,
        func.count(ThreatIndicator.id)
    ).filter(ThreatIndicator.is_active == True).group_by(ThreatIndicator.indicator_type).all()
    
    type_dict = {t.value: 0 for t in IndicatorType}
    for itype, count in type_counts:
        type_dict[itype.value] = count
    
    return {
        "total_indicators": total,
        "malicious_count": malicious,
        "safe_count": total - malicious,
        "by_risk_level": risk_dict,
        "by_type": type_dict
    }
