"""
Database Models for ThreatEye
SQLAlchemy ORM models with security best practices
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, JSON, 
    ForeignKey, Index, Enum as SQLEnum, UniqueConstraint
)
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func
import enum


class Base(DeclarativeBase):
    """Base class for all models"""
    pass


class ThreatCategory(enum.Enum):
    """Threat categories enumeration"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    C2 = "c2"
    SPAM = "spam"
    SCANNING = "scanning"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class RiskLevel(enum.Enum):
    """Risk level enumeration"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IndicatorType(enum.Enum):
    """Type of threat indicator"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class FeedSource(enum.Enum):
    """Threat intelligence feed sources"""
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    OTX = "otx"
    MANUAL = "manual"


# ============================================
# Core Tables
# ============================================

class ThreatIndicator(Base):
    """
    Main table for threat indicators (IPs/Domains)
    Stores core indicator data with security attributes
    """
    __tablename__ = "threat_indicators"
    
    # Primary Key
    id = Column(Integer, primary_key=True, index=True)
    
    # Indicator Details
    indicator_type = Column(SQLEnum(IndicatorType), nullable=False, index=True)
    indicator_value = Column(String(255), nullable=False, index=True)  # IP or Domain
    
    # Risk Assessment
    threat_score = Column(Float, default=0.0, nullable=False, index=True)  # 0-100
    risk_level = Column(SQLEnum(RiskLevel), default=RiskLevel.SAFE, nullable=False, index=True)
    is_malicious = Column(Boolean, default=False, nullable=False, index=True)
    
    # Categorization
    primary_category = Column(SQLEnum(ThreatCategory), default=ThreatCategory.UNKNOWN, nullable=False)
    categories = Column(JSON, default=list)  # List of all applicable categories
    
    # Status & Tracking
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_analyzed = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Cross-Feed Correlation
    feed_hits = Column(Integer, default=0)  # Number of feeds that flagged this
    confidence_score = Column(Float, default=0.0)  # ML confidence
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    feed_data = relationship("FeedData", back_populates="indicator", cascade="all, delete-orphan")
    enrichment = relationship("EnrichmentData", back_populates="indicator", uselist=False, cascade="all, delete-orphan")
    ml_predictions = relationship("MLPrediction", back_populates="indicator", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="indicator", cascade="all, delete-orphan")
    
    # Constraints & Indexes
    __table_args__ = (
        UniqueConstraint('indicator_type', 'indicator_value', name='uix_indicator_type_value'),
        Index('idx_threat_score_risk', 'threat_score', 'risk_level'),
        Index('idx_active_malicious', 'is_active', 'is_malicious'),
        Index('idx_last_seen', 'last_seen'),
    )
    
    def __repr__(self):
        return f"<ThreatIndicator(type={self.indicator_type.value}, value={self.indicator_value}, score={self.threat_score})>"


class FeedData(Base):
    """
    Raw data from threat intelligence feeds
    Stores original feed responses for audit and correlation
    """
    __tablename__ = "feed_data"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Feed Information
    feed_source = Column(SQLEnum(FeedSource), nullable=False, index=True)
    feed_timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Feed Response
    is_malicious = Column(Boolean, nullable=False)
    reputation_score = Column(Float)  # Feed's own score (if available)
    detection_count = Column(Integer)  # e.g., VT detection ratio
    total_engines = Column(Integer)   # e.g., VT total engines
    
    # Raw Data (for audit and debugging)
    raw_response = Column(JSON)  # Complete API response
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    indicator = relationship("ThreatIndicator", back_populates="feed_data")
    
    # Indexes
    __table_args__ = (
        Index('idx_feed_source_timestamp', 'feed_source', 'feed_timestamp'),
    )
    
    def __repr__(self):
        return f"<FeedData(source={self.feed_source.value}, malicious={self.is_malicious})>"


class EnrichmentData(Base):
    """
    Enrichment data (WHOIS, GeoIP, ASN)
    One-to-one with ThreatIndicator
    """
    __tablename__ = "enrichment_data"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # WHOIS Data
    whois_registrar = Column(String(255))
    whois_creation_date = Column(DateTime(timezone=True))
    whois_expiration_date = Column(DateTime(timezone=True))
    whois_updated_date = Column(DateTime(timezone=True))
    whois_registrant = Column(String(500))
    domain_age_days = Column(Integer)
    
    # GeoIP Data
    geo_country = Column(String(100), index=True)
    geo_country_code = Column(String(10), index=True)
    geo_city = Column(String(100))
    geo_region = Column(String(100))
    geo_latitude = Column(Float)
    geo_longitude = Column(Float)
    geo_timezone = Column(String(50))
    
    # ASN Data
    asn_number = Column(Integer, index=True)
    asn_name = Column(String(255))
    asn_organization = Column(String(500))
    
    # ISP/Network
    isp_name = Column(String(255))
    network_range = Column(String(50))
    
    # DNS Data
    dns_records = Column(JSON)  # A, MX, NS records
    reverse_dns = Column(String(255))
    
    # Metadata
    enriched_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    indicator = relationship("ThreatIndicator", back_populates="enrichment")
    
    # Indexes
    __table_args__ = (
        Index('idx_geo_country_asn', 'geo_country_code', 'asn_number'),
    )
    
    def __repr__(self):
        return f"<EnrichmentData(country={self.geo_country}, asn={self.asn_number})>"


class MLPrediction(Base):
    """
    Machine Learning predictions and anomaly detection results
    """
    __tablename__ = "ml_predictions"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Model Information
    model_name = Column(String(100), nullable=False)
    model_version = Column(String(50))
    
    # Classification Results
    predicted_class = Column(String(50))  # safe/suspicious/malicious
    confidence = Column(Float, nullable=False)  # 0-1
    probability_safe = Column(Float)
    probability_suspicious = Column(Float)
    probability_malicious = Column(Float)
    
    # Anomaly Detection
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float)  # Higher = more anomalous
    
    # Feature Importance (top features that influenced prediction)
    feature_importance = Column(JSON)
    
    # Metadata
    predicted_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    indicator = relationship("ThreatIndicator", back_populates="ml_predictions")
    
    def __repr__(self):
        return f"<MLPrediction(class={self.predicted_class}, confidence={self.confidence})>"


# ============================================
# Alert & Notification Tables
# ============================================

class Alert(Base):
    """
    Security alerts triggered by high-risk indicators
    """
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Alert Details
    severity = Column(SQLEnum(RiskLevel), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Trigger Information
    triggered_by = Column(String(100))  # e.g., "threshold_exceeded", "anomaly_detected"
    trigger_value = Column(Float)  # The value that triggered the alert
    threshold = Column(Float)  # The threshold that was exceeded
    
    # Status
    is_acknowledged = Column(Boolean, default=False, nullable=False, index=True)
    acknowledged_by = Column(String(100))
    acknowledged_at = Column(DateTime(timezone=True))
    
    is_resolved = Column(Boolean, default=False, nullable=False, index=True)
    resolved_by = Column(String(100))
    resolved_at = Column(DateTime(timezone=True))
    resolution_notes = Column(Text)
    
    # Notification Status
    notification_sent = Column(Boolean, default=False)
    notification_channels = Column(JSON)  # email, slack, etc.
    notification_timestamp = Column(DateTime(timezone=True))
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    indicator = relationship("ThreatIndicator", back_populates="alerts")
    
    # Indexes
    __table_args__ = (
        Index('idx_alert_status', 'is_acknowledged', 'is_resolved', 'severity'),
        Index('idx_alert_created', 'created_at'),
    )
    
    def __repr__(self):
        return f"<Alert(severity={self.severity.value}, title={self.title})>"


class UserActivity(Base):
    """
    User activity and audit log
    Tracks who did what and when for security compliance
    """
    __tablename__ = "user_activity"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # User Information
    user_id = Column(String(100), index=True)
    username = Column(String(100), index=True)
    user_ip = Column(String(50))
    
    # Activity Details
    activity_type = Column(String(100), nullable=False, index=True)  # login, search, alert_ack, etc.
    activity_description = Column(Text)
    resource_type = Column(String(50))  # indicator, alert, report
    resource_id = Column(Integer)
    
    # Request Details
    http_method = Column(String(10))
    endpoint = Column(String(255))
    request_data = Column(JSON)
    response_status = Column(Integer)
    
    # Metadata
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_user_activity', 'user_id', 'activity_type', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<UserActivity(user={self.username}, type={self.activity_type})>"


class ScanJob(Base):
    """
    Background scan/collection jobs
    Tracks scheduled and on-demand scans
    """
    __tablename__ = "scan_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Job Details
    job_type = Column(String(50), nullable=False, index=True)  # feed_sync, enrichment, ml_scan
    job_status = Column(String(50), nullable=False, index=True)  # pending, running, completed, failed
    
    # Scope
    feed_source = Column(SQLEnum(FeedSource))
    indicators_processed = Column(Integer, default=0)
    indicators_total = Column(Integer)
    
    # Results
    new_threats_found = Column(Integer, default=0)
    alerts_triggered = Column(Integer, default=0)
    errors_count = Column(Integer, default=0)
    error_log = Column(Text)
    
    # Timing
    started_at = Column(DateTime(timezone=True), index=True)
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index('idx_job_status_created', 'job_status', 'created_at'),
    )
    
    def __repr__(self):
        return f"<ScanJob(type={self.job_type}, status={self.job_status})>"


class Report(Base):
    """
    Generated reports (PDF/CSV)
    """
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Report Details
    report_type = Column(String(50), nullable=False, index=True)  # daily, weekly, custom
    report_format = Column(String(20), nullable=False)  # pdf, csv, json
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Time Range
    date_from = Column(DateTime(timezone=True), nullable=False)
    date_to = Column(DateTime(timezone=True), nullable=False)
    
    # Statistics
    total_indicators = Column(Integer, default=0)
    malicious_count = Column(Integer, default=0)
    alerts_count = Column(Integer, default=0)
    
    # File Information
    file_path = Column(String(500))
    file_size_bytes = Column(Integer)
    
    # Access Control
    generated_by = Column(String(100))
    is_public = Column(Boolean, default=False)
    
    # Metadata
    generated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True))
    
    def __repr__(self):
        return f"<Report(type={self.report_type}, format={self.report_format})>"


# ============================================
# Configuration & Settings Tables
# ============================================

class SystemConfig(Base):
    """
    System-wide configuration settings
    """
    __tablename__ = "system_config"
    
    id = Column(Integer, primary_key=True, index=True)
    
    config_key = Column(String(100), unique=True, nullable=False, index=True)
    config_value = Column(JSON, nullable=False)
    config_type = Column(String(50))  # string, integer, boolean, json
    description = Column(Text)
    
    is_sensitive = Column(Boolean, default=False)  # Don't log in audit
    
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    updated_by = Column(String(100))
    
    def __repr__(self):
        return f"<SystemConfig(key={self.config_key})>"
