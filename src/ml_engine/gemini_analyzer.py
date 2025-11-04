"""
Google Gemini AI Threat Analyzer
Uses Gemini AI for advanced threat intelligence analysis
"""

import google.generativeai as genai
from typing import Dict, Any, List, Optional
import json


class GeminiThreatAnalyzer:
    """
    Real AI-powered threat analysis using Google Gemini
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize Gemini AI with API key"""
        self.api_key = api_key
        self.model = None
        
        if api_key and api_key != "YOUR_GEMINI_API_KEY_HERE":
            try:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
                self.enabled = True
            except Exception as e:
                print(f"Failed to initialize Gemini: {e}")
                self.enabled = False
        else:
            self.enabled = False
    
    def analyze_threat(
        self,
        indicator_value: str,
        indicator_type: str,
        threat_score: float,
        external_sources: List[Dict[str, Any]],
        risk_factors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Use Gemini AI to analyze threat and provide intelligent insights
        
        Args:
            indicator_value: IP/domain/URL being analyzed
            indicator_type: Type of indicator
            threat_score: Calculated threat score
            external_sources: Data from external APIs
            risk_factors: Identified risk factors
            
        Returns:
            Dict with AI-generated insights, recommendations, and analysis
        """
        
        if not self.enabled or not self.model:
            return {
                'enabled': False,
                'insights': ['Gemini AI not configured - using heuristic analysis only'],
                'recommendations': [],
                'analysis': 'AI analysis unavailable'
            }
        
        try:
            # Build context for Gemini
            prompt = self._build_analysis_prompt(
                indicator_value,
                indicator_type,
                threat_score,
                external_sources,
                risk_factors
            )
            
            # Get AI analysis from Gemini
            response = self.model.generate_content(prompt)
            analysis_text = response.text
            
            # Parse AI response
            parsed = self._parse_ai_response(analysis_text)
            
            return {
                'enabled': True,
                'insights': parsed.get('insights', []),
                'recommendations': parsed.get('recommendations', []),
                'analysis': parsed.get('analysis', ''),
                'threat_classification': parsed.get('classification', ''),
                'confidence_assessment': parsed.get('confidence', '')
            }
            
        except Exception as e:
            print(f"Gemini analysis failed: {e}")
            return {
                'enabled': False,
                'error': str(e),
                'insights': ['AI analysis temporarily unavailable'],
                'recommendations': [],
                'analysis': 'Error during AI analysis'
            }
    
    def _build_analysis_prompt(
        self,
        indicator_value: str,
        indicator_type: str,
        threat_score: float,
        external_sources: List[Dict[str, Any]],
        risk_factors: List[Dict[str, Any]]
    ) -> str:
        """Build detailed prompt for Gemini AI"""
        
        # Summarize external sources
        sources_summary = []
        for source in external_sources:
            sources_summary.append(
                f"- {source.get('source')}: "
                f"{'Malicious' if source.get('is_malicious') else 'Clean'} "
                f"(Score: {source.get('threat_score', 0):.1f})"
            )
        
        # Summarize risk factors
        risks_summary = []
        for risk in risk_factors:
            risks_summary.append(
                f"- [{risk.get('severity', 'unknown').upper()}] "
                f"{risk.get('factor', '')}: {risk.get('details', '')}"
            )
        
        prompt = f"""You are a cybersecurity threat intelligence analyst. Analyze this threat indicator and provide expert insights.

**INDICATOR DETAILS:**
- Type: {indicator_type.upper()}
- Value: {indicator_value}
- Calculated Threat Score: {threat_score:.2f}/100

**EXTERNAL THREAT INTELLIGENCE:**
{chr(10).join(sources_summary) if sources_summary else '- No external sources available'}

**IDENTIFIED RISK FACTORS:**
{chr(10).join(risks_summary) if risks_summary else '- No specific risk factors identified'}

**ANALYSIS REQUIRED:**
Please provide a comprehensive cybersecurity assessment in the following JSON format:

{{
  "insights": [
    "3-5 concise, actionable insights about this threat (use emojis for visual clarity)"
  ],
  "recommendations": [
    "2-4 specific security recommendations for defenders"
  ],
  "analysis": "A 2-3 sentence expert analysis explaining the threat level and context",
  "classification": "One of: APT/Malware/Phishing/Spam/Suspicious/Benign/Unknown",
  "confidence": "Your confidence level: High/Medium/Low with brief explanation"
}}

Be specific, technical, and actionable. Focus on what security teams need to know."""
        
        return prompt
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """Parse Gemini's response into structured data"""
        
        try:
            # Try to extract JSON from response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            
            if start != -1 and end > start:
                json_str = response_text[start:end]
                return json.loads(json_str)
            
            # If no JSON, create structured response from text
            return {
                'insights': [line.strip() for line in response_text.split('\n') if line.strip() and len(line.strip()) > 20][:5],
                'recommendations': [],
                'analysis': response_text[:500],
                'classification': 'Unknown',
                'confidence': 'Medium'
            }
            
        except Exception as e:
            print(f"Failed to parse Gemini response: {e}")
            return {
                'insights': ['AI analysis completed but response format was unexpected'],
                'recommendations': [],
                'analysis': response_text[:500] if response_text else 'No analysis available',
                'classification': 'Unknown',
                'confidence': 'Low'
            }


# Global instance
gemini_analyzer = None

def get_gemini_analyzer(api_key: Optional[str] = None) -> GeminiThreatAnalyzer:
    """Get or create Gemini analyzer instance"""
    global gemini_analyzer
    
    if gemini_analyzer is None:
        gemini_analyzer = GeminiThreatAnalyzer(api_key)
    
    return gemini_analyzer
