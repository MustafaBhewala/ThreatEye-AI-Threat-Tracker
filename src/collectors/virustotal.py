"""
VirusTotal Feed Collector
Collects threat intelligence from VirusTotal API
"""

import aiohttp
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from src.collectors.base import BaseFeedCollector
from src.storage.models import IndicatorType, ThreatCategory, ConfidenceLevel

logger = logging.getLogger(__name__)


class VirusTotalCollector(BaseFeedCollector):
    """VirusTotal threat intelligence collector"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    async def fetch_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent malicious files and URLs from VirusTotal
        
        Args:
            limit: Maximum number of threats to fetch
            
        Returns:
            List of threat data from VirusTotal
        """
        threats = []
        
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get recent malicious files
                url = f"{self.BASE_URL}/intelligence/search"
                params = {
                    "query": "type:file and positives:10+",
                    "limit": min(limit // 2, 40)  # VirusTotal has rate limits
                }
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        threats.extend(data.get('data', []))
                        logger.info(f"Fetched {len(data.get('data', []))} malicious files from VirusTotal")
                    else:
                        logger.error(f"VirusTotal API error: {response.status}")
                
                # Get recent malicious URLs
                params = {
                    "query": "type:url and positives:5+",
                    "limit": min(limit // 2, 40)
                }
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        threats.extend(data.get('data', []))
                        logger.info(f"Fetched {len(data.get('data', []))} malicious URLs from VirusTotal")
                    else:
                        logger.error(f"VirusTotal API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error fetching from VirusTotal: {e}")
        
        return threats
    
    def parse_threat(self, raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse VirusTotal data into standardized format
        
        Args:
            raw_data: Raw data from VirusTotal
            
        Returns:
            Parsed threat data
        """
        try:
            attributes = raw_data.get('attributes', {})
            
            # Extract indicator value
            indicator_value = None
            indicator_type = None
            
            if raw_data.get('type') == 'file':
                indicator_value = attributes.get('sha256') or attributes.get('sha1') or attributes.get('md5')
                indicator_type = IndicatorType.URL  # Using URL for file hashes
            elif raw_data.get('type') == 'url':
                indicator_value = attributes.get('url')
                # Extract domain from URL
                if indicator_value and '://' in indicator_value:
                    indicator_value = indicator_value.split('://')[1].split('/')[0]
                indicator_type = IndicatorType.DOMAIN
            elif raw_data.get('type') == 'domain':
                indicator_value = attributes.get('domain') or raw_data.get('id')
                indicator_type = IndicatorType.DOMAIN
            elif raw_data.get('type') == 'ip_address':
                indicator_value = attributes.get('ip_address') or raw_data.get('id')
                indicator_type = IndicatorType.IP
            
            if not indicator_value:
                return None
            
            # Calculate threat score
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) if stats else 1
            threat_score = (malicious / total * 100) if total > 0 else 0
            
            # Determine category
            categories = attributes.get('categories', {})
            primary_category = ThreatCategory.MALWARE
            if 'phishing' in str(categories).lower():
                primary_category = ThreatCategory.PHISHING
            
            # Extract tags
            tags = attributes.get('tags', [])
            if isinstance(tags, list):
                tags = [str(tag) for tag in tags[:10]]  # Limit to 10 tags
            else:
                tags = []
            
            # Add VirusTotal tag
            tags.append('virustotal')
            
            parsed = {
                'indicator_value': indicator_value,
                'indicator_type': indicator_type,
                'threat_score': min(threat_score, 100),
                'is_malicious': malicious > 0,
                'confidence_level': ConfidenceLevel.HIGH if malicious >= 5 else ConfidenceLevel.MEDIUM,
                'primary_category': primary_category,
                'tags': tags,
                'enrichment': {
                    'geo_country': attributes.get('country'),
                    'asn': attributes.get('asn'),
                    'org': attributes.get('as_owner'),
                    'reputation_score': threat_score,
                    'whois_data': attributes.get('whois'),
                    'dns_records': attributes.get('dns_records'),
                }
            }
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing VirusTotal data: {e}")
            return None
