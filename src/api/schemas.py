"""
Pydantic Schemas for API Request/Response Models
Data validation and serialization
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


# Enums
class IndicatorTypeEnum(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class RiskLevelEnum(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategoryEnum(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    C2 = "c2"
    SPAM = "spam"
    SCANNING = "scanning"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


# Response Models
class ThreatIndicatorResponse(BaseModel):
    """Response model for threat indicator"""
    id: int
    indicator_type: IndicatorTypeEnum
    indicator_value: str
    threat_score: float
    risk_level: RiskLevelEnum
    is_malicious: bool
    primary_category: ThreatCategoryEnum
    categories: List[str] = []
    feed_hits: int
    confidence_score: float
    first_seen: datetime
    last_seen: datetime
    last_analyzed: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class EnrichmentDataResponse(BaseModel):
    """Response model for enrichment data"""
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_city: Optional[str] = None
    asn_number: Optional[int] = None
    asn_name: Optional[str] = None
    asn_organization: Optional[str] = None
    isp_name: Optional[str] = None
    whois_registrar: Optional[str] = None
    domain_age_days: Optional[int] = None
    
    class Config:
        from_attributes = True


class ThreatIndicatorDetailResponse(ThreatIndicatorResponse):
    """Detailed response with enrichment data"""
    enrichment: Optional[EnrichmentDataResponse] = None


class AlertResponse(BaseModel):
    """Response model for alert"""
    id: int
    indicator_id: int
    severity: RiskLevelEnum
    title: str
    description: Optional[str] = None
    triggered_by: Optional[str] = None
    is_acknowledged: bool
    is_resolved: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class DashboardStatsResponse(BaseModel):
    """Response model for dashboard statistics"""
    total_indicators: int
    malicious_count: int
    safe_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    active_alerts: int
    total_alerts: int
    last_scan: Optional[datetime] = None


class PaginatedResponse(BaseModel):
    """Generic paginated response"""
    total: int
    page: int
    page_size: int
    total_pages: int
    data: List[ThreatIndicatorResponse]


# Request Models
class ThreatIndicatorCreate(BaseModel):
    """Request model for creating a threat indicator"""
    indicator_type: IndicatorTypeEnum
    indicator_value: str
    threat_score: Optional[float] = 0.0
    risk_level: Optional[RiskLevelEnum] = RiskLevelEnum.SAFE
    is_malicious: Optional[bool] = False
    primary_category: Optional[ThreatCategoryEnum] = ThreatCategoryEnum.UNKNOWN


class ScanRequest(BaseModel):
    """Request model for scanning an indicator"""
    indicator_value: str
    indicator_type: Optional[IndicatorTypeEnum] = None
