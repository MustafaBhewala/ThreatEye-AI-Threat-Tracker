"""
Base Feed Collector
Abstract base class for all threat intelligence feed collectors
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from sqlalchemy.orm import Session

from src.storage.models import ThreatIndicator, FeedData, EnrichmentData
from src.storage.models import IndicatorType, RiskLevel, ThreatCategory, ConfidenceLevel

logger = logging.getLogger(__name__)


class BaseFeedCollector(ABC):
    """Abstract base class for feed collectors"""
    
    def __init__(self, api_key: str, db_session: Session):
        self.api_key = api_key
        self.db_session = db_session
        self.source_name = self.__class__.__name__.replace('Collector', '')
        
    @abstractmethod
    async def fetch_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch threats from the feed source
        
        Args:
            limit: Maximum number of threats to fetch
            
        Returns:
            List of threat data dictionaries
        """
        pass
    
    @abstractmethod
    def parse_threat(self, raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse raw threat data into standardized format
        
        Args:
            raw_data: Raw data from the feed source
            
        Returns:
            Parsed threat data or None if invalid
        """
        pass
    
    def calculate_risk_level(self, threat_score: float) -> RiskLevel:
        """Calculate risk level based on threat score"""
        if threat_score >= 90:
            return RiskLevel.CRITICAL
        elif threat_score >= 70:
            return RiskLevel.HIGH
        elif threat_score >= 40:
            return RiskLevel.MEDIUM
        elif threat_score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def determine_indicator_type(self, value: str) -> IndicatorType:
        """Determine indicator type from value"""
        import re
        
        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        # Domain pattern
        domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        
        if re.match(ip_pattern, value):
            return IndicatorType.IP
        elif re.match(domain_pattern, value):
            return IndicatorType.DOMAIN
        else:
            return IndicatorType.URL
    
    def save_threat_indicator(self, threat_data: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """
        Save or update threat indicator in database
        
        Args:
            threat_data: Parsed threat data
            
        Returns:
            ThreatIndicator instance or None
        """
        try:
            indicator_value = threat_data['indicator_value']
            
            # Check if indicator already exists
            existing = self.db_session.query(ThreatIndicator).filter(
                ThreatIndicator.indicator_value == indicator_value
            ).first()
            
            if existing:
                # Update existing indicator
                existing.threat_score = max(existing.threat_score, threat_data.get('threat_score', 0))
                existing.risk_level = self.calculate_risk_level(existing.threat_score)
                existing.last_seen = datetime.utcnow()
                existing.is_malicious = threat_data.get('is_malicious', False)
                
                # Update tags
                if threat_data.get('tags'):
                    existing_tags = set(existing.tags or [])
                    new_tags = set(threat_data['tags'])
                    existing.tags = list(existing_tags | new_tags)
                
                self.db_session.commit()
                logger.info(f"Updated existing indicator: {indicator_value}")
                return existing
            else:
                # Create new indicator
                indicator = ThreatIndicator(
                    indicator_value=indicator_value,
                    indicator_type=threat_data.get('indicator_type', self.determine_indicator_type(indicator_value)),
                    threat_score=threat_data.get('threat_score', 0),
                    risk_level=self.calculate_risk_level(threat_data.get('threat_score', 0)),
                    confidence_level=threat_data.get('confidence_level', ConfidenceLevel.MEDIUM),
                    is_malicious=threat_data.get('is_malicious', False),
                    primary_category=threat_data.get('primary_category', ThreatCategory.UNKNOWN),
                    tags=threat_data.get('tags', []),
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                )
                
                self.db_session.add(indicator)
                self.db_session.commit()
                logger.info(f"Created new indicator: {indicator_value}")
                return indicator
                
        except Exception as e:
            logger.error(f"Error saving threat indicator: {e}")
            self.db_session.rollback()
            return None
    
    def save_feed_data(self, indicator_id: int, raw_data: Dict[str, Any]) -> Optional[FeedData]:
        """
        Save raw feed data
        
        Args:
            indicator_id: Associated threat indicator ID
            raw_data: Raw data from feed source
            
        Returns:
            FeedData instance or None
        """
        try:
            from src.storage.models import FeedSource
            
            # Map source name to FeedSource enum
            feed_source_map = {
                'VirusTotal': FeedSource.VIRUSTOTAL,
                'AbuseIPDB': FeedSource.ABUSEIPDB,
                'OTX': FeedSource.OTX
            }
            
            feed_data = FeedData(
                indicator_id=indicator_id,
                feed_source=feed_source_map.get(self.source_name, FeedSource.MANUAL),
                feed_timestamp=datetime.utcnow(),
                is_malicious=raw_data.get('is_malicious', False),
                reputation_score=raw_data.get('reputation_score'),
                detection_count=raw_data.get('detection_count'),
                total_engines=raw_data.get('total_engines'),
                raw_response=raw_data
            )
            
            self.db_session.add(feed_data)
            self.db_session.commit()
            return feed_data
            
        except Exception as e:
            logger.error(f"Error saving feed data: {e}")
            self.db_session.rollback()
            return None
    
    def save_enrichment_data(self, indicator_id: int, enrichment: Dict[str, Any]) -> Optional[EnrichmentData]:
        """
        Save enrichment data
        
        Args:
            indicator_id: Associated threat indicator ID
            enrichment: Enrichment data dictionary
            
        Returns:
            EnrichmentData instance or None
        """
        try:
            # Check if enrichment already exists
            existing = self.db_session.query(EnrichmentData).filter(
                EnrichmentData.indicator_id == indicator_id
            ).first()
            
            # Map enrichment fields to database columns
            enrichment_fields = {
                'geo_country': enrichment.get('geo_country'),
                'geo_country_code': enrichment.get('geo_country'),  # Use same for now
                'geo_city': enrichment.get('geo_city'),
                'geo_latitude': enrichment.get('geo_latitude'),
                'geo_longitude': enrichment.get('geo_longitude'),
                'asn_number': enrichment.get('asn'),
                'asn_organization': enrichment.get('org'),
                'isp_name': enrichment.get('org'),
                'dns_records': enrichment.get('dns_records'),
                'whois_registrar': enrichment.get('whois_data'),
            }
            
            # Remove None values
            enrichment_fields = {k: v for k, v in enrichment_fields.items() if v is not None}
            
            if existing:
                # Update existing enrichment
                for key, value in enrichment_fields.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                existing.updated_at = datetime.utcnow()
                self.db_session.commit()
                return existing
            else:
                # Create new enrichment
                enrichment_data = EnrichmentData(
                    indicator_id=indicator_id,
                    **enrichment_fields
                )
                
                self.db_session.add(enrichment_data)
                self.db_session.commit()
                return enrichment_data
                
        except Exception as e:
            logger.error(f"Error saving enrichment data: {e}")
            self.db_session.rollback()
            return None
    
    async def collect(self, limit: int = 100) -> Dict[str, Any]:
        """
        Main collection method
        
        Args:
            limit: Maximum number of threats to collect
            
        Returns:
            Collection statistics
        """
        stats = {
            'source': self.source_name,
            'collected': 0,
            'new': 0,
            'updated': 0,
            'errors': 0,
            'start_time': datetime.utcnow()
        }
        
        try:
            logger.info(f"Starting collection from {self.source_name}")
            
            # Fetch threats from source
            raw_threats = await self.fetch_threats(limit)
            
            for raw_threat in raw_threats:
                try:
                    # Parse threat data
                    parsed = self.parse_threat(raw_threat)
                    if not parsed:
                        continue
                    
                    # Save threat indicator
                    indicator = self.save_threat_indicator(parsed)
                    if indicator:
                        stats['collected'] += 1
                        
                        # Save raw feed data
                        self.save_feed_data(indicator.id, raw_threat)
                        
                        # Save enrichment data if available
                        if parsed.get('enrichment'):
                            self.save_enrichment_data(indicator.id, parsed['enrichment'])
                    
                except Exception as e:
                    logger.error(f"Error processing threat: {e}")
                    stats['errors'] += 1
                    continue
            
            stats['end_time'] = datetime.utcnow()
            stats['duration'] = (stats['end_time'] - stats['start_time']).total_seconds()
            
            logger.info(f"Collection complete: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Collection failed: {e}")
            stats['error'] = str(e)
            return stats
