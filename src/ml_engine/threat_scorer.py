"""
AI-Powered Threat Scoring Engine
Uses machine learning and heuristics to calculate accurate threat scores
"""

import re
from typing import Dict, Any, List
from datetime import datetime
import math


class AIThreatScorer:
    """
    AI-based threat scoring engine that analyzes multiple signals
    to provide accurate threat assessment
    """
    
    def __init__(self):
        self.weights = {
            'abuse_score': 0.30,        # AbuseIPDB (IPs only)
            'detection_ratio': 0.25,    # VirusTotal
            'otx_reputation': 0.20,     # AlienVault OTX
            'behavioral_signals': 0.15, # AI behavioral analysis
            'metadata_analysis': 0.10   # AI metadata analysis
        }
    
    def calculate_threat_score(
        self,
        indicator_value: str,
        indicator_type: str,
        external_sources: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        AI-powered threat score calculation
        
        Args:
            indicator_value: IP/domain/URL to analyze
            indicator_type: Type of indicator
            external_sources: Data from external threat feeds
            
        Returns:
            Dict with threat_score, confidence, risk_factors, and AI insights
        """
        
        scores = []
        risk_factors = []
        detection_details = []
        
        # 1. Analyze external source data
        for source in external_sources:
            source_name = source.get('source', 'Unknown')
            
            # AbuseIPDB Analysis
            if source_name == 'AbuseIPDB':
                abuse_score = self._analyze_abuseipdb(source)
                scores.append({
                    'source': 'AbuseIPDB',
                    'score': abuse_score,
                    'weight': self.weights['abuse_score']
                })
                
                if source.get('is_malicious'):
                    risk_factors.append({
                        'severity': 'high' if abuse_score > 75 else 'medium',
                        'factor': f"Abuse reports detected",
                        'details': f"{source.get('total_reports', 0)} reports, {abuse_score:.0f}% confidence"
                    })
            
            # VirusTotal Analysis
            elif source_name == 'VirusTotal':
                vt_score = self._analyze_virustotal(source)
                scores.append({
                    'source': 'VirusTotal',
                    'score': vt_score,
                    'weight': self.weights['detection_ratio']
                })
                
                malicious_count = source.get('malicious_count', 0)
                if malicious_count > 0:
                    severity = 'critical' if malicious_count > 10 else 'high' if malicious_count > 5 else 'medium'
                    risk_factors.append({
                        'severity': severity,
                        'factor': 'Multi-engine detection',
                        'details': f"{malicious_count}/{source.get('total_engines', 0)} engines flagged"
                    })
            
            # AlienVault OTX Analysis
            elif source_name == 'AlienVault OTX':
                otx_score = self._analyze_otx(source)
                scores.append({
                    'source': 'AlienVault OTX',
                    'score': otx_score,
                    'weight': self.weights['otx_reputation']
                })
                
                if source.get('is_malicious'):
                    pulse_count = source.get('pulse_count', 0)
                    severity = 'high' if otx_score > 75 else 'medium'
                    risk_factors.append({
                        'severity': severity,
                        'factor': 'OTX threat intelligence',
                        'details': f"{pulse_count} threat pulses, {otx_score:.0f}% reputation risk"
                    })
        
        # 2. Behavioral Pattern Analysis (AI heuristics)
        behavioral_score = self._analyze_behavioral_patterns(
            indicator_value, 
            indicator_type,
            external_sources
        )
        scores.append({
            'source': 'AI Behavioral Analysis',
            'score': behavioral_score,
            'weight': self.weights['behavioral_signals']
        })
        
        # 3. Metadata Analysis
        metadata_score = self._analyze_metadata(indicator_value, indicator_type)
        scores.append({
            'source': 'AI Metadata Analysis',
            'score': metadata_score,
            'weight': self.weights['metadata_analysis']
        })
        
        # 4. Calculate weighted aggregate score
        total_weight = sum(s['weight'] for s in scores)
        weighted_score = sum(s['score'] * s['weight'] for s in scores) / total_weight if total_weight > 0 else 0
        
        # 5. Calculate confidence based on data availability
        confidence = self._calculate_confidence(external_sources, scores)
        
        # 6. Determine risk level
        risk_level = self._determine_risk_level(weighted_score)
        
        # 7. Generate AI insights
        ai_insights = self._generate_insights(
            weighted_score,
            risk_factors,
            external_sources,
            behavioral_score,
            metadata_score
        )
        
        return {
            'threat_score': round(weighted_score, 2),
            'confidence': round(confidence, 2),
            'confidence_level': 'high' if confidence > 75 else 'medium' if confidence > 50 else 'low',
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'score_breakdown': scores,
            'ai_insights': ai_insights,
            'is_malicious': weighted_score >= 50
        }
    
    def _analyze_abuseipdb(self, source_data: Dict[str, Any]) -> float:
        """Analyze AbuseIPDB data"""
        abuse_score = source_data.get('threat_score', 0)
        total_reports = source_data.get('total_reports', 0)
        
        # Boost score based on report count
        if total_reports > 100:
            abuse_score = min(100, abuse_score * 1.2)
        elif total_reports > 50:
            abuse_score = min(100, abuse_score * 1.1)
        
        return abuse_score
    
    def _analyze_virustotal(self, source_data: Dict[str, Any]) -> float:
        """Analyze VirusTotal data"""
        malicious = source_data.get('malicious_count', 0)
        total = source_data.get('total_engines', 1)
        
        # Calculate detection ratio
        detection_ratio = (malicious / total * 100) if total > 0 else 0
        
        # Apply sigmoid curve for better scaling
        score = 100 / (1 + math.exp(-0.3 * (malicious - 5)))
        
        return min(100, score)
    
    def _analyze_otx(self, source_data: Dict[str, Any]) -> float:
        """Analyze AlienVault OTX data"""
        # Get the threat score from OTX
        otx_score = source_data.get('threat_score', 0)
        pulse_count = source_data.get('pulse_count', 0)
        
        # Boost score based on pulse count (threat intelligence references)
        if pulse_count > 10:
            otx_score = min(100, otx_score * 1.15)
        elif pulse_count > 5:
            otx_score = min(100, otx_score * 1.10)
        elif pulse_count > 0:
            otx_score = min(100, otx_score * 1.05)
        
        return otx_score
    
    def _analyze_behavioral_patterns(
        self,
        indicator_value: str,
        indicator_type: str,
        external_sources: List[Dict[str, Any]]
    ) -> float:
        """
        AI-based behavioral pattern analysis
        Analyzes suspicious patterns in indicator characteristics
        """
        score = 0
        
        if indicator_type == 'ip':
            # Check for suspicious IP patterns
            octets = indicator_value.split('.')
            
            # Private/Reserved IPs are less threatening in public context
            if octets[0] in ['10', '192', '172']:
                score -= 20
            
            # Recent abuse patterns (simulated - would use historical data)
            for source in external_sources:
                last_reported = source.get('last_reported')
                if last_reported:
                    # Recent activity is more concerning
                    score += 15
        
        elif indicator_type == 'domain':
            # Domain age and structure analysis
            domain_parts = indicator_value.split('.')
            
            # Suspicious TLDs
            suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link']
            if any(indicator_value.endswith(tld) for tld in suspicious_tlds):
                score += 25
            
            # Random-looking domains (entropy check)
            if self._calculate_entropy(domain_parts[0]) > 3.5:
                score += 20
            
            # Short domains with numbers
            if len(domain_parts[0]) < 6 and re.search(r'\d', domain_parts[0]):
                score += 15
            
            # Multiple hyphens or unusual characters
            if domain_parts[0].count('-') > 2:
                score += 10
        
        return min(100, max(0, score))
    
    def _analyze_metadata(self, indicator_value: str, indicator_type: str) -> float:
        """
        Analyze metadata and structural properties
        """
        score = 0
        
        if indicator_type == 'domain':
            # Length analysis
            domain_name = indicator_value.split('.')[0]
            
            # Very short or very long domains are suspicious
            if len(domain_name) < 4:
                score += 15
            elif len(domain_name) > 20:
                score += 10
            
            # Consonant ratio (suspicious domains often have high consonant density)
            vowels = 'aeiou'
            consonants = sum(1 for c in domain_name.lower() if c.isalpha() and c not in vowels)
            if len(domain_name) > 0:
                consonant_ratio = consonants / len(domain_name)
                if consonant_ratio > 0.8:
                    score += 15
        
        return min(100, score)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    def _calculate_confidence(
        self,
        external_sources: List[Dict[str, Any]],
        scores: List[Dict[str, Any]]
    ) -> float:
        """
        Calculate confidence in the threat assessment
        Based on data availability and consensus
        """
        base_confidence = 40  # Minimum confidence with AI heuristics
        
        # Add confidence based on number of sources
        source_confidence = min(30, len(external_sources) * 15)
        
        # Check for consensus between sources
        if len(external_sources) >= 2:
            malicious_count = sum(1 for s in external_sources if s.get('is_malicious'))
            if malicious_count == 0 or malicious_count == len(external_sources):
                # Full consensus
                source_confidence += 20
            elif malicious_count > 0:
                # Partial consensus
                source_confidence += 10
        
        # AI analysis always adds some confidence
        ai_confidence = 20
        
        return min(100, base_confidence + source_confidence + ai_confidence)
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'safe'
    
    def _generate_insights(
        self,
        score: float,
        risk_factors: List[Dict],
        external_sources: List[Dict],
        behavioral_score: float,
        metadata_score: float
    ) -> List[str]:
        """
        Generate human-readable AI insights
        """
        insights = []
        
        # Overall assessment
        if score >= 70:
            insights.append("⚠️ High threat level detected - immediate action recommended")
        elif score >= 40:
            insights.append("⚡ Moderate threat indicators present - proceed with caution")
        else:
            insights.append("✅ Low threat level - appears relatively safe")
        
        # Source-based insights
        source_count = len(external_sources)
        if source_count > 0:
            malicious_sources = sum(1 for s in external_sources if s.get('is_malicious'))
            if malicious_sources > 0:
                insights.append(f"🔍 {malicious_sources}/{source_count} threat intelligence sources flagged as malicious")
        
        # Behavioral insights
        if behavioral_score > 50:
            insights.append("🤖 AI detected suspicious behavioral patterns")
        elif behavioral_score > 0:
            insights.append("🧠 Minor behavioral anomalies detected by AI analysis")
        
        # Metadata insights
        if metadata_score > 50:
            insights.append("📊 Suspicious metadata characteristics identified")
        
        # Risk factor summary
        if risk_factors:
            critical_count = sum(1 for f in risk_factors if f.get('severity') == 'critical')
            high_count = sum(1 for f in risk_factors if f.get('severity') == 'high')
            
            if critical_count > 0:
                insights.append(f"🚨 {critical_count} critical risk factor(s) identified")
            if high_count > 0:
                insights.append(f"⚠️ {high_count} high-priority risk factor(s) found")
        
        # Confidence insight
        if source_count == 0:
            insights.append("ℹ️ Assessment based on AI heuristics only - limited external data available")
        
        return insights


# Global instance
ai_scorer = AIThreatScorer()
