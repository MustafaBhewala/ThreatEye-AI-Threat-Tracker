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
from src.ml_engine.threat_scorer import ai_scorer
from src.ml_engine.gemini_analyzer import get_gemini_analyzer

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


async def check_otx(indicator: str, api_key: str, indicator_type: IndicatorType) -> Dict[str, Any]:
    """Check indicator against AlienVault OTX"""
    if not api_key:
        return {}
    
    headers = {"X-OTX-API-KEY": api_key}
    
    try:
        async with aiohttp.ClientSession() as session:
            if indicator_type == IndicatorType.IP:
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
            elif indicator_type == IndicatorType.DOMAIN:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
            else:
                return {}
            
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    pulse_count = data.get('pulse_info', {}).get('count', 0)
                    reputation = data.get('reputation', 0)
                    
                    # Calculate threat score from pulses (each pulse = 10%, max 100%)
                    threat_score = min(pulse_count * 10, 100)
                    is_malicious = pulse_count > 0 or reputation < 0
                    
                    return {
                        'source': 'AlienVault OTX',
                        'is_malicious': is_malicious,
                        'threat_score': threat_score,
                        'pulse_count': pulse_count,
                        'reputation': reputation
                    }
    except Exception as e:
        print(f"OTX check failed: {e}")
    
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
    
    # Check if exists in database (for reference, but still scan externally)
    existing = db.query(ThreatIndicator).filter(
        ThreatIndicator.indicator_value == indicator_value,
        ThreatIndicator.is_active == True
    ).first()
    
    found_in_db = existing is not None
    if existing:
        # Update last_analyzed
        existing.last_analyzed = datetime.utcnow()
        db.commit()
    
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
    
    # Check AlienVault OTX
    otx_result = await check_otx(
        indicator_value,
        api_keys.get('otx'),
        indicator_type
    )
    if otx_result:
        external_results.append(otx_result)
        threat_scores.append(otx_result.get('threat_score', 0))
        if otx_result.get('is_malicious'):
            is_malicious = True
    
    # 🤖 AI-POWERED THREAT ANALYSIS
    ai_analysis = ai_scorer.calculate_threat_score(
        indicator_value,
        indicator_type.value,
        external_results
    )
    
    # Use AI-calculated scores (more accurate than simple average)
    avg_threat_score = ai_analysis['threat_score']
    is_malicious = ai_analysis['is_malicious']
    confidence_level_value = ai_analysis['confidence_level']
    
    # 🤖 GOOGLE GEMINI AI ANALYSIS (Real AI!)
    gemini_api_key = api_keys.get('gemini')
    gemini = get_gemini_analyzer(gemini_api_key)
    gemini_result = gemini.analyze_threat(
        indicator_value,
        indicator_type.value,
        avg_threat_score,
        external_results,
        ai_analysis.get('risk_factors', [])
    )
    
    # 🎯 AI PREDICTION FUSION - Combine Mathematical + Gemini AI
    # If Gemini has high confidence and disagrees significantly, use Gemini's prediction
    if gemini_result.get('enabled') and gemini_result.get('confidence') in ['High', 'high']:
        gemini_score = gemini_result.get('ai_threat_score', avg_threat_score)
        gemini_malicious = gemini_result.get('is_malicious', is_malicious)
        
        # If Gemini disagrees significantly (>30 point difference), use weighted average
        score_diff = abs(gemini_score - avg_threat_score)
        if score_diff > 30:
            # Gemini overrides with 60% weight, Mathematical gets 40% weight
            final_score = (gemini_score * 0.6) + (avg_threat_score * 0.4)
            avg_threat_score = round(final_score, 2)
            is_malicious = gemini_malicious
            confidence_level_value = 'high'
            
            # Add explanation to AI insights
            ai_analysis['ai_insights'].insert(0, 
                f"🤖 AI Override: Gemini AI detected significant threat discrepancy. "
                f"Adjusted score from {ai_analysis['threat_score']:.1f} to {avg_threat_score:.1f} "
                f"based on advanced pattern recognition."
            )
    
    # Create temporary result object with AI-enhanced data
    result = {
        'found_in_database': found_in_db,
        'indicator': {
            'id': existing.id if existing else None,
            'indicator_type': indicator_type.value,
            'indicator_value': indicator_value,
            'threat_score': avg_threat_score,
            'risk_level': ai_analysis['risk_level'],
            'is_malicious': is_malicious,
            'primary_category': existing.primary_category.value if existing else ThreatCategory.UNKNOWN.value,
            'confidence_level': confidence_level_value,
            'categories': [],
            'feed_hits': len(external_results),
            'confidence_score': ai_analysis['confidence'],
            'first_seen': existing.first_seen if existing else datetime.utcnow(),
            'last_seen': existing.last_seen if existing else datetime.utcnow(),
            'last_analyzed': datetime.utcnow(),
            'created_at': existing.created_at if existing else datetime.utcnow(),
            'updated_at': datetime.utcnow()
        },
        'external_sources': external_results,
        'enrichment': None,
        'ai_analysis': {
            'risk_factors': ai_analysis.get('risk_factors', []),
            'insights': ai_analysis.get('ai_insights', []),
            'confidence': round(ai_analysis['confidence'], 2),
            'calculation_breakdown': {
                'methodology': 'Multi-Factor Weighted AI Analysis',
                'components': [
                    {'factor': 'Abuse Score', 'weight': '35%', 'description': 'Reputation from abuse reports and blacklists'},
                    {'factor': 'Detection Ratio', 'weight': '30%', 'description': 'Multi-engine consensus from security vendors'},
                    {'factor': 'Reputation Score', 'weight': '15%', 'description': 'Historical behavior and negative indicators'},
                    {'factor': 'Behavioral Analysis', 'weight': '12%', 'description': 'AI heuristics: IP patterns, domain entropy, suspicious TLDs'},
                    {'factor': 'Metadata Analysis', 'weight': '8%', 'description': 'Shannon entropy, consonant ratio, structure anomalies'}
                ],
                'confidence_formula': 'Base (40%) + Sources (15% each, max 30%) + Consensus Bonus (20%) + AI Enhancement (20%)',
                'risk_levels': {
                    'critical': '≥90 - Immediate threat, confirmed malicious',
                    'high': '70-89 - High confidence threat, action recommended',
                    'medium': '40-69 - Moderate risk, investigation needed',
                    'low': '20-39 - Low risk, minor concerns',
                    'safe': '<20 - Minimal to no threat detected'
                }
            }
        },
        'gemini_ai': gemini_result
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
    
    # Optionally save to database if malicious and not already saved
    if is_malicious and avg_threat_score >= 50 and not found_in_db:
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
    elif found_in_db:
        result['saved_to_database'] = False  # Already in database
    
    return result
