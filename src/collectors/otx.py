"""
AlienVault OTX Feed Collector
Collects threat intelligence from AlienVault Open Threat Exchange
"""

import aiohttp
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from src.collectors.base import BaseFeedCollector
from src.storage.models import IndicatorType, ThreatCategory, ConfidenceLevel

logger = logging.getLogger(__name__)


class OTXCollector(BaseFeedCollector):
    """AlienVault OTX threat intelligence collector"""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    async def fetch_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch threat pulses from AlienVault OTX
        
        Args:
            limit: Maximum number of threats to fetch
            
        Returns:
            List of threat data from OTX
        """
        threats = []
        
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get subscribed pulses (threat feeds)
                url = f"{self.BASE_URL}/pulses/subscribed"
                params = {
                    "limit": 50,  # Get recent pulses
                    "page": 1
                }
                
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        pulses = data.get('results', [])
                        
                        # Extract indicators from each pulse
                        for pulse in pulses:
                            indicators = pulse.get('indicators', [])
                            for indicator in indicators[:limit]:  # Limit per pulse
                                # Add pulse metadata to each indicator
                                indicator['pulse_name'] = pulse.get('name')
                                indicator['pulse_description'] = pulse.get('description')
                                indicator['pulse_tags'] = pulse.get('tags', [])
                                indicator['pulse_created'] = pulse.get('created')
                                threats.append(indicator)
                                
                                if len(threats) >= limit:
                                    break
                            
                            if len(threats) >= limit:
                                break
                        
                        logger.info(f"Fetched {len(threats)} indicators from {len(pulses)} OTX pulses")
                    else:
                        logger.error(f"OTX API error: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error fetching from OTX: {e}")
        
        return threats
    
    def parse_threat(self, raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse OTX data into standardized format
        
        Args:
            raw_data: Raw data from OTX
            
        Returns:
            Parsed threat data
        """
        try:
            indicator_value = raw_data.get('indicator')
            indicator_type_str = raw_data.get('type', '').lower()
            
            if not indicator_value:
                return None
            
            # Map OTX indicator types to our types
            type_mapping = {
                'ipv4': IndicatorType.IP,
                'ipv6': IndicatorType.IP,
                'domain': IndicatorType.DOMAIN,
                'hostname': IndicatorType.DOMAIN,
                'url': IndicatorType.URL,
                'uri': IndicatorType.URL,
            }
            
            indicator_type = type_mapping.get(indicator_type_str, IndicatorType.URL)
            
            # Calculate threat score based on OTX data
            # OTX doesn't provide scores, so we estimate based on pulse metadata
            threat_score = 50  # Base score
            
            # Adjust score based on tags and categories
            tags = raw_data.get('pulse_tags', [])
            if any(tag.lower() in ['malware', 'ransomware', 'trojan'] for tag in tags):
                threat_score += 30
            if any(tag.lower() in ['phishing', 'scam'] for tag in tags):
                threat_score += 25
            if any(tag.lower() in ['apt', 'targeted'] for tag in tags):
                threat_score += 20
            
            threat_score = min(threat_score, 100)
            
            # Determine primary category from tags
            primary_category = ThreatCategory.UNKNOWN
            for tag in tags:
                tag_lower = tag.lower()
                if 'malware' in tag_lower or 'trojan' in tag_lower:
                    primary_category = ThreatCategory.MALWARE
                    break
                elif 'phishing' in tag_lower:
                    primary_category = ThreatCategory.PHISHING
                    break
                elif 'botnet' in tag_lower or 'c2' in tag_lower or 'c&c' in tag_lower:
                    primary_category = ThreatCategory.C2
                    break
                elif 'ddos' in tag_lower:
                    primary_category = ThreatCategory.DDOS
                    break
                elif 'scan' in tag_lower:
                    primary_category = ThreatCategory.SCANNING
                    break
            
            # Build complete tag list
            all_tags = ['otx'] + [str(tag) for tag in tags[:10]]
            
            # Add pulse name as tag if available
            pulse_name = raw_data.get('pulse_name')
            if pulse_name:
                all_tags.append(f"pulse:{pulse_name[:30]}")
            
            # Determine if malicious
            is_malicious = threat_score >= 50
            
            # Confidence based on threat score
            if threat_score >= 70:
                confidence = ConfidenceLevel.HIGH
            elif threat_score >= 40:
                confidence = ConfidenceLevel.MEDIUM
            else:
                confidence = ConfidenceLevel.LOW
            
            parsed = {
                'indicator_value': indicator_value,
                'indicator_type': indicator_type,
                'threat_score': threat_score,
                'is_malicious': is_malicious,
                'confidence_level': confidence,
                'primary_category': primary_category,
                'tags': all_tags,
                'enrichment': {
                    'org': raw_data.get('content', ''),
                    'description': raw_data.get('pulse_description', ''),
                    'first_seen_otx': raw_data.get('pulse_created'),
                    'otx_pulse': pulse_name,
                }
            }
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing OTX data: {e}")
            return None
