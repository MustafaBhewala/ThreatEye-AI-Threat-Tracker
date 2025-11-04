"""
AbuseIPDB Feed Collector
Collects IP abuse reports from AbuseIPDB
"""

import aiohttp
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from src.collectors.base import BaseFeedCollector
from src.storage.models import IndicatorType, ThreatCategory, ConfidenceLevel

logger = logging.getLogger(__name__)


class AbuseIPDBCollector(BaseFeedCollector):
    """AbuseIPDB threat intelligence collector"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    async def fetch_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch blacklisted IPs from AbuseIPDB
        
        Args:
            limit: Maximum number of threats to fetch
            
        Returns:
            List of threat data from AbuseIPDB
        """
        threats = []
        
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get blacklisted IPs
                url = f"{self.BASE_URL}/blacklist"
                params = {
                    "confidenceMinimum": 75,  # Only high-confidence threats
                    "limit": min(limit, 10000)  # AbuseIPDB allows up to 10k
                }
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        threats = data.get('data', [])
                        logger.info(f"Fetched {len(threats)} blacklisted IPs from AbuseIPDB")
                    elif response.status == 429:
                        logger.warning("AbuseIPDB rate limit exceeded")
                    else:
                        error_text = await response.text()
                        logger.error(f"AbuseIPDB API error: {response.status} - {error_text}")
                        
        except Exception as e:
            logger.error(f"Error fetching from AbuseIPDB: {e}")
        
        return threats
    
    def parse_threat(self, raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse AbuseIPDB data into standardized format
        
        Args:
            raw_data: Raw data from AbuseIPDB
            
        Returns:
            Parsed threat data
        """
        try:
            ip_address = raw_data.get('ipAddress')
            if not ip_address:
                return None
            
            # Get abuse confidence score (0-100)
            abuse_score = raw_data.get('abuseConfidenceScore', 0)
            
            # Map abuse categories to threat categories
            categories = raw_data.get('categories', [])
            primary_category = ThreatCategory.MALICIOUS_IP
            
            # AbuseIPDB category mapping
            if 18 in categories or 19 in categories:  # Brute force
                primary_category = ThreatCategory.BRUTE_FORCE
            elif 14 in categories or 15 in categories:  # Port scan
                primary_category = ThreatCategory.SCANNING
            elif 10 in categories:  # DDoS
                primary_category = ThreatCategory.DDOS
            elif 11 in categories:  # Spam
                primary_category = ThreatCategory.SPAM
            
            # Determine if malicious
            is_malicious = abuse_score >= 75
            
            # Build tags from categories
            tags = ['abuseipdb']
            category_names = {
                3: 'fraud',
                4: 'ddos',
                9: 'phishing',
                10: 'ddos-attack',
                11: 'spam',
                14: 'port-scan',
                15: 'hacking',
                18: 'brute-force',
                19: 'bad-web-bot',
                20: 'exploited-host',
                21: 'web-app-attack',
                22: 'ssh-attack',
                23: 'iot-targeted'
            }
            
            for cat_id in categories:
                if cat_id in category_names:
                    tags.append(category_names[cat_id])
            
            # Determine confidence level
            if abuse_score >= 90:
                confidence = ConfidenceLevel.HIGH
            elif abuse_score >= 75:
                confidence = ConfidenceLevel.MEDIUM
            else:
                confidence = ConfidenceLevel.LOW
            
            parsed = {
                'indicator_value': ip_address,
                'indicator_type': IndicatorType.IP,
                'threat_score': abuse_score,
                'is_malicious': is_malicious,
                'confidence_level': confidence,
                'primary_category': primary_category,
                'tags': tags,
                'enrichment': {
                    'geo_country': raw_data.get('countryCode'),
                    'geo_city': None,
                    'geo_latitude': None,
                    'geo_longitude': None,
                    'asn': None,
                    'org': raw_data.get('isp'),
                    'domain': raw_data.get('domain'),
                    'usage_type': raw_data.get('usageType'),
                    'is_tor': raw_data.get('isTor', False),
                    'is_whitelisted': raw_data.get('isWhitelisted', False),
                    'total_reports': raw_data.get('totalReports', 0),
                    'num_distinct_users': raw_data.get('numDistinctUsers', 0),
                    'last_reported': raw_data.get('lastReportedAt'),
                }
            }
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing AbuseIPDB data: {e}")
            return None
