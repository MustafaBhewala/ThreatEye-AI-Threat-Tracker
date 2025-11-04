"""
Scan API Router
Real-time threat intelligence scanning for external indicators
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict, Any
import aiohttp
import re
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.storage.database import get_db
from src.storage.models import (
    ThreatIndicator, IndicatorType, RiskLevel, ThreatCategory, ConfidenceLevel
)
from src.api.schemas import ThreatIndicatorDetailResponse

router = APIRouter()


def determine_indicator_type(value: str) -> IndicatorType:
    """Determine if value is IP, domain, or URL"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    
    if re.match(ip_pattern, value):
        return IndicatorType.IP
    elif re.match(domain_pattern, value):
        return IndicatorType.DOMAIN
    else:
        return IndicatorType.URL


def calculate_risk_level(score: float) -> RiskLevel:
    """Calculate risk level from threat score"""
    if score >= 90:
        return RiskLevel.CRITICAL
    elif score >= 70:
        return RiskLevel.HIGH
    elif score >= 40:
        return RiskLevel.MEDIUM
    elif score >= 20:
        return RiskLevel.LOW
    else:
        return RiskLevel.SAFE


async def check_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """Check IP against AbuseIPDB"""
    if not api_key:
        return {}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    result = data.get('data', {})
                    
                    abuse_score = result.get('abuseConfidenceScore', 0)
                    is_malicious = abuse_score > 50
                    
                    return {
                        'source': 'AbuseIPDB',
                        'is_malicious': is_malicious,
                        'threat_score': abuse_score,
                        'total_reports': result.get('totalReports', 0),
                        'country': result.get('countryCode'),
                        'isp': result.get('isp'),
                        'domain': result.get('domain'),
                        'usage_type': result.get('usageType'),
                        'last_reported': result.get('lastReportedAt')
                    }
    except Exception as e:
        print(f"AbuseIPDB check failed: {e}")
    
    return {}


async def check_virustotal(indicator: str, api_key: str, indicator_type: IndicatorType) -> Dict[str, Any]:
    """Check indicator against VirusTotal"""
    if not api_key:
        return {}
    
    headers = {"x-apikey": api_key}
    
    try:
        async with aiohttp.ClientSession() as session:
            if indicator_type == IndicatorType.IP:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
            elif indicator_type == IndicatorType.DOMAIN:
                url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
            else:
                return {}
            
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values())
                    
                    return {
                        'source': 'VirusTotal',
                        'is_malicious': malicious > 0,
                        'threat_score': (malicious / total * 100) if total > 0 else 0,
                        'malicious_count': malicious,
                        'total_engines': total,
                        'reputation': attributes.get('reputation', 0),
                        'categories': attributes.get('categories', {})
                    }
    except Exception as e:
        print(f"VirusTotal check failed: {e}")
    
    return {}


@router.post("/live")
async def scan_live(
    indicator_value: str,
    db: Session = Depends(get_db)
):
    """
    Perform live threat intelligence scan on any indicator
    Checks both local database and external threat feeds
    """
    indicator_value = indicator_value.strip()
    indicator_type = determine_indicator_type(indicator_value)
    
    # First check local database
    existing = db.query(ThreatIndicator).filter(
        ThreatIndicator.indicator_value == indicator_value,
        ThreatIndicator.is_active == True
    ).first()
    
    if existing:
        # Update last_analyzed
        existing.last_analyzed = datetime.utcnow()
        db.commit()
        
        return {
            'found_in_database': True,
            'indicator': existing,
            'external_sources': []
        }
    
    # Load API keys from config
    import json
    try:
        with open('config/config.json', 'r') as f:
            config = json.load(f)
            api_keys = config.get('api_keys', {})
    except:
        api_keys = {}
    
    # Perform external checks
    external_results = []
    threat_scores = []
    is_malicious = False
    
    # Check AbuseIPDB for IPs
    if indicator_type == IndicatorType.IP:
        abuseipdb_result = await check_abuseipdb(
            indicator_value, 
            api_keys.get('abuseipdb')
        )
        if abuseipdb_result:
            external_results.append(abuseipdb_result)
            threat_scores.append(abuseipdb_result.get('threat_score', 0))
            if abuseipdb_result.get('is_malicious'):
                is_malicious = True
    
    # Check VirusTotal
    vt_result = await check_virustotal(
        indicator_value,
        api_keys.get('virustotal'),
        indicator_type
    )
    if vt_result:
        external_results.append(vt_result)
        threat_scores.append(vt_result.get('threat_score', 0))
        if vt_result.get('is_malicious'):
            is_malicious = True
    
    # Calculate aggregate threat score
    avg_threat_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0
    
    # Create temporary result object
    result = {
        'found_in_database': False,
        'indicator': {
            'id': None,
            'indicator_type': indicator_type.value,
            'indicator_value': indicator_value,
            'threat_score': avg_threat_score,
            'risk_level': calculate_risk_level(avg_threat_score).value,
            'is_malicious': is_malicious,
            'primary_category': ThreatCategory.UNKNOWN.value,
            'confidence_level': ConfidenceLevel.MEDIUM.value if external_results else ConfidenceLevel.LOW.value,
            'categories': [],
            'feed_hits': len(external_results),
            'confidence_score': len(external_results) * 25.0,  # 25% per source
            'first_seen': datetime.utcnow(),
            'last_seen': datetime.utcnow(),
            'last_analyzed': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        'external_sources': external_results,
        'enrichment': None
    }
    
    # Extract enrichment data from external sources
    if external_results:
        enrichment = {}
        for source_data in external_results:
            if source_data.get('country'):
                enrichment['geo_country'] = source_data['country']
                enrichment['geo_country_code'] = source_data['country']
            if source_data.get('isp'):
                enrichment['isp_name'] = source_data['isp']
        
        if enrichment:
            result['enrichment'] = enrichment
    
    # Optionally save to database if malicious
    if is_malicious and avg_threat_score >= 50:
        try:
            new_indicator = ThreatIndicator(
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                threat_score=avg_threat_score,
                risk_level=calculate_risk_level(avg_threat_score),
                confidence_level=ConfidenceLevel.MEDIUM,
                is_malicious=True,
                primary_category=ThreatCategory.SUSPICIOUS,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                last_analyzed=datetime.utcnow()
            )
            db.add(new_indicator)
            db.commit()
            result['indicator']['id'] = new_indicator.id
            result['saved_to_database'] = True
        except Exception as e:
            print(f"Failed to save indicator: {e}")
            result['saved_to_database'] = False
    
    return result
