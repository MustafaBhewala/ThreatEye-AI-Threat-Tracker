import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { indicatorsApi, scanApi } from '../api/client';
import { Search, AlertTriangle, Shield, Globe, MapPin, Server, Calendar, Activity, ExternalLink, Zap, Brain, Lightbulb } from 'lucide-react';

const Scan = () => {
  const [searchValue, setSearchValue] = useState('');
  const [result, setResult] = useState(null);

  const liveScanMutation = useMutation({
    mutationFn: (value) => scanApi.liveScan(value),
    onSuccess: (data) => {
      // Transform the response to match the expected format
      if (data.indicator) {
        setResult({
          ...data.indicator,
          enrichment: data.enrichment,
          external_sources: data.external_sources,
          ai_analysis: data.ai_analysis,
          gemini_ai: data.gemini_ai,
          found_in_database: data.found_in_database,
          saved_to_database: data.saved_to_database
        });
      } else {
        // No threat found
        setResult({ 
          error: true, 
          message: 'No threat data available',
          indicator_value: data.indicator_value || 'Unknown'
        });
      }
    },
    onError: (error) => {
      console.error('Scan error:', error);
      setResult({ 
        error: true, 
        message: error.response?.data?.detail || error.message || 'Failed to scan indicator' 
      });
    },
  });

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchValue.trim()) {
      liveScanMutation.mutate(searchValue.trim());
    }
  };

  const isLoading = liveScanMutation.isPending;

  const getRiskBadge = (riskLevel) => {
    const badges = {
      critical: 'bg-red-950/50 text-red-300 border border-red-900',
      high: 'bg-red-900/30 text-red-400 border border-red-800',
      medium: 'bg-yellow-900/30 text-yellow-400 border border-yellow-800',
      low: 'bg-blue-900/30 text-blue-400 border border-blue-800',
      safe: 'bg-green-900/30 text-green-400 border border-green-800',
    };
    return badges[riskLevel] || badges.safe;
  };

  const getTypeBadge = (type) => {
    const badges = {
      ip: 'bg-purple-900/30 text-purple-400 border border-purple-800',
      domain: 'bg-cyan-900/30 text-cyan-400 border border-cyan-800',
      url: 'bg-indigo-900/30 text-indigo-400 border border-indigo-800',
    };
    return badges[type] || badges.ip;
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-3xl font-bold text-white mb-2">Threat Intelligence Lookup</h1>
        <p className="text-gray-400">Search for IP addresses, domains, or URLs in our threat database</p>
      </div>

      {/* Search Form */}
      <div className="bg-dark-card rounded-lg border border-gray-700 p-8">
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Enter IP address, domain, or URL for AI-powered analysis..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="w-full pl-12 pr-4 py-4 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 placeholder-gray-500 focus:outline-none focus:border-primary-600 focus:ring-2 focus:ring-primary-600 text-lg"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-4 rounded-lg font-medium text-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed bg-linear-to-r from-green-600 to-primary-600 text-white hover:from-green-700 hover:to-primary-700"
          >
            {isLoading ? (
              <span className="flex items-center justify-center space-x-2">
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                <span>Analyzing with AI...</span>
              </span>
            ) : (
              <span className="flex items-center justify-center space-x-2">
                <Brain className="w-5 h-5" />
                <span>Scan with AI-Powered Analysis</span>
              </span>
            )}
          </button>
        </form>
        
        <div className="mt-4 flex items-center justify-center space-x-2 text-sm text-gray-400">
          <Shield className="w-4 h-4 text-green-500" />
          <span>Checks database + 3 live threat intelligence sources with AI analysis</span>
        </div>
        
        <div className="mt-6 flex items-center space-x-4 text-sm text-gray-400">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4" />
            <span>Examples:</span>
          </div>
          <button
            onClick={() => setSearchValue('8.8.8.8')}
            className="text-primary-500 hover:text-primary-400 transition-colors"
          >
            8.8.8.8
          </button>
          <button
            onClick={() => setSearchValue('malware.com')}
            className="text-primary-500 hover:text-primary-400 transition-colors"
          >
            malware.com
          </button>
          <button
            onClick={() => setSearchValue('192.168.1.100')}
            className="text-primary-500 hover:text-primary-400 transition-colors"
          >
            192.168.1.100
          </button>
        </div>
      </div>

      {/* Results */}
      {result && (
        <div className="bg-dark-card rounded-lg border border-gray-700 overflow-hidden">
          {result.error ? (
            <div className="p-12 text-center">
              <Shield className="w-20 h-20 mx-auto mb-4 text-green-500 opacity-50" />
              <h3 className="text-xl font-bold text-white mb-2">No Threats Found</h3>
              <p className="text-gray-400">
                This indicator is not in our threat database.
              </p>
              <p className="text-gray-500 text-sm mt-2">
                This doesn't guarantee safety - always exercise caution.
              </p>
            </div>
          ) : (
            <div className="p-8 space-y-6">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    {result.is_malicious ? (
                      <AlertTriangle className="w-8 h-8 text-red-400" />
                    ) : (
                      <Shield className="w-8 h-8 text-green-400" />
                    )}
                    <h2 className="text-2xl font-bold text-white font-mono">{result.indicator_value}</h2>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getTypeBadge(result.indicator_type)}`}>
                      {result.indicator_type.toUpperCase()}
                    </span>
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRiskBadge(result.risk_level)}`}>
                      {result.risk_level.toUpperCase()} RISK
                    </span>
                    {result.is_malicious && (
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-950/50 text-red-300 border border-red-900">
                        MALICIOUS
                      </span>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-4xl font-bold text-white mb-1">{result.threat_score.toFixed(1)}</div>
                  <div className="text-sm text-gray-400">Threat Score</div>
                </div>
              </div>

              {/* Key Info Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center space-x-2 mb-2">
                    <Activity className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-400 text-sm">Category</span>
                  </div>
                  <div className="text-white font-medium capitalize">{result.primary_category.replace('_', ' ')}</div>
                </div>

                <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center space-x-2 mb-2">
                    <Calendar className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-400 text-sm">First Seen</span>
                  </div>
                  <div className="text-white font-medium">{new Date(result.first_seen).toLocaleDateString()}</div>
                </div>

                <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center space-x-2 mb-2">
                    <Calendar className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-400 text-sm">Last Seen</span>
                  </div>
                  <div className="text-white font-medium">{new Date(result.last_seen).toLocaleDateString()}</div>
                </div>

                <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                  <div className="flex items-center space-x-2 mb-2">
                    <Globe className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-400 text-sm">Confidence</span>
                  </div>
                  <div className="text-white font-medium">{result.confidence_level.toUpperCase()}</div>
                </div>
              </div>

              {/* Enrichment Data */}
              {result.enrichment && (result.enrichment.geo_country || result.enrichment.asn_number || result.enrichment.isp_name) && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                    <Globe className="w-5 h-5" />
                    <span>Enrichment Data</span>
                  </h3>
                  <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                      {result.enrichment.geo_country && (
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <MapPin className="w-4 h-4 text-gray-400" />
                            <span className="text-gray-400 text-sm">Country</span>
                          </div>
                          <div className="text-white">{result.enrichment.geo_country} {result.enrichment.geo_country_code ? `(${result.enrichment.geo_country_code})` : ''}</div>
                        </div>
                      )}
                      {result.enrichment.geo_city && (
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <MapPin className="w-4 h-4 text-gray-400" />
                            <span className="text-gray-400 text-sm">City</span>
                          </div>
                          <div className="text-white">{result.enrichment.geo_city}</div>
                        </div>
                      )}
                      {result.enrichment.asn_number && (
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <Server className="w-4 h-4 text-gray-400" />
                            <span className="text-gray-400 text-sm">ASN</span>
                          </div>
                          <div className="text-white">AS{result.enrichment.asn_number}</div>
                        </div>
                      )}
                      {result.enrichment.asn_name && (
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <Server className="w-4 h-4 text-gray-400" />
                            <span className="text-gray-400 text-sm">ASN Name</span>
                          </div>
                          <div className="text-white">{result.enrichment.asn_name}</div>
                        </div>
                      )}
                      {result.enrichment.isp_name && (
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <Server className="w-4 h-4 text-gray-400" />
                            <span className="text-gray-400 text-sm">ISP</span>
                          </div>
                          <div className="text-white">{result.enrichment.isp_name}</div>
                        </div>
                      )}
                      {result.enrichment.whois_registrar && (
                        <div>
                          <div className="flex items-center space-x-2 mb-1">
                            <Globe className="w-4 h-4 text-gray-400" />
                            <span className="text-gray-400 text-sm">Registrar</span>
                          </div>
                          <div className="text-white">{result.enrichment.whois_registrar}</div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* External Sources from Live Scan */}
              {result.external_sources && result.external_sources.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                    <Zap className="w-5 h-5 text-green-500" />
                    <span>Live Threat Intelligence Sources</span>
                  </h3>
                  {result.external_sources.map((source, idx) => (
                    <div key={idx} className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <div className={`w-2 h-2 rounded-full ${source.is_malicious ? 'bg-red-500' : 'bg-green-500'}`}></div>
                          <span className="text-primary-500 font-medium">{source.source}</span>
                        </div>
                        <span className={`px-3 py-1 rounded text-sm font-medium ${
                          source.is_malicious 
                            ? 'bg-red-900/50 text-red-300' 
                            : 'bg-green-900/50 text-green-300'
                        }`}>
                          {source.is_malicious ? 'MALICIOUS' : 'CLEAN'}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
                        {source.threat_score !== undefined && (
                          <div>
                            <span className="text-gray-400">Threat Score:</span>
                            <span className="text-white font-medium ml-2">{source.threat_score.toFixed(0)}%</span>
                          </div>
                        )}
                        {source.total_reports !== undefined && (
                          <div>
                            <span className="text-gray-400">Reports:</span>
                            <span className="text-white font-medium ml-2">{source.total_reports}</span>
                          </div>
                        )}
                        {source.malicious_count !== undefined && (
                          <div>
                            <span className="text-gray-400">Detections:</span>
                            <span className="text-white font-medium ml-2">{source.malicious_count}/{source.total_engines}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                  {result.found_in_database === false && result.saved_to_database && (
                    <div className="bg-green-900/20 border border-green-900/50 rounded-lg p-3 flex items-center space-x-2">
                      <Shield className="w-5 h-5 text-green-400" />
                      <span className="text-green-300 text-sm">This threat has been saved to the database for future reference</span>
                    </div>
                  )}
                  {result.found_in_database && (
                    <div className="bg-blue-900/20 border border-blue-900/50 rounded-lg p-3 flex items-center space-x-2">
                      <Activity className="w-5 h-5 text-blue-400" />
                      <span className="text-blue-300 text-sm">This indicator was found in our database</span>
                    </div>
                  )}
                </div>
              )}

              {/* AI Analysis Section */}
              {result.ai_analysis && (result.ai_analysis.insights?.length > 0 || result.ai_analysis.risk_factors?.length > 0) && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                    <Brain className="w-5 h-5 text-purple-500" />
                    <span>AI-Powered Analysis</span>
                    <span className="text-xs px-2 py-1 bg-purple-900/50 text-purple-300 rounded-full">
                      {result.ai_analysis.confidence}% Confidence
                    </span>
                  </h3>
                  
                  {/* AI Insights */}
                  {result.ai_analysis.insights && result.ai_analysis.insights.length > 0 && (
                    <div className="bg-linear-to-br from-purple-950/30 to-blue-950/30 rounded-lg p-4 border border-purple-900/50">
                      <h4 className="text-purple-300 font-medium mb-3 flex items-center space-x-2">
                        <Lightbulb className="w-4 h-4" />
                        <span>AI Insights</span>
                      </h4>
                      <div className="space-y-2">
                        {result.ai_analysis.insights.map((insight, idx) => (
                          <div key={idx} className="flex items-start space-x-2 text-gray-200">
                            <span className="mt-0.5">•</span>
                            <span className="text-sm">{insight}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Risk Factors */}
                  {result.ai_analysis.risk_factors && result.ai_analysis.risk_factors.length > 0 && (
                    <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                      <h4 className="text-red-400 font-medium mb-3 flex items-center space-x-2">
                        <AlertTriangle className="w-4 h-4" />
                        <span>Identified Risk Factors</span>
                      </h4>
                      <div className="space-y-3">
                        {result.ai_analysis.risk_factors.map((risk, idx) => (
                          <div key={idx} className="flex items-start space-x-3">
                            <span className={`px-2 py-1 rounded text-xs font-medium uppercase shrink-0 ${
                              risk.severity === 'critical' ? 'bg-red-900/50 text-red-300' :
                              risk.severity === 'high' ? 'bg-orange-900/50 text-orange-300' :
                              risk.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                              'bg-gray-700 text-gray-300'
                            }`}>
                              {risk.severity}
                            </span>
                            <div className="flex-1">
                              <div className="text-white font-medium text-sm">{risk.factor}</div>
                              <div className="text-gray-400 text-xs mt-1">{risk.details}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* AI Calculation Methodology */}
                  {result.ai_analysis.calculation_breakdown && (
                    <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                      <h4 className="text-purple-400 font-medium mb-3 flex items-center space-x-2">
                        <Brain className="w-4 h-4" />
                        <span>How AI Calculates Risk</span>
                      </h4>
                      
                      {/* Methodology */}
                      <div className="mb-4">
                        <div className="text-sm font-medium text-gray-300 mb-2">
                          {result.ai_analysis.calculation_breakdown.methodology}
                        </div>
                      </div>
                      
                      {/* Components */}
                      <div className="space-y-2 mb-4">
                        <div className="text-xs font-medium text-gray-400 uppercase tracking-wider">Weighted Factors:</div>
                        {result.ai_analysis.calculation_breakdown.components.map((comp, idx) => (
                          <div key={idx} className="flex items-start space-x-2 text-sm">
                            <span className="text-primary-400 font-mono">{comp.weight}</span>
                            <div>
                              <span className="text-white font-medium">{comp.factor}:</span>
                              <span className="text-gray-400 ml-1">{comp.description}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                      
                      {/* Confidence Formula */}
                      <div className="mb-4 p-3 bg-dark-bg/50 rounded border border-gray-800">
                        <div className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Confidence Formula:</div>
                        <div className="text-sm text-gray-300 font-mono">
                          {result.ai_analysis.calculation_breakdown.confidence_formula}
                        </div>
                      </div>
                      
                      {/* Risk Levels */}
                      <div>
                        <div className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Risk Level Thresholds:</div>
                        <div className="space-y-1">
                          {Object.entries(result.ai_analysis.calculation_breakdown.risk_levels).map(([level, desc]) => (
                            <div key={level} className="flex items-start space-x-2 text-xs">
                              <span className={`px-2 py-0.5 rounded uppercase font-medium ${
                                level === 'critical' ? 'bg-red-900/50 text-red-300' :
                                level === 'high' ? 'bg-orange-900/50 text-orange-300' :
                                level === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                                level === 'low' ? 'bg-blue-900/50 text-blue-300' :
                                'bg-green-900/50 text-green-300'
                              }`}>
                                {level}
                              </span>
                              <span className="text-gray-400">{desc}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Google Gemini AI Analysis */}
              {result.gemini_ai && result.gemini_ai.enabled && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                    <Brain className="w-5 h-5 text-blue-500 animate-pulse" />
                    <span>Google Gemini AI Prediction</span>
                    <span className="text-xs px-2 py-1 bg-blue-900/50 text-blue-300 rounded-full">
                      Real AI
                    </span>
                  </h3>
                  
                  {/* AI Prediction Badge */}
                  {result.gemini_ai.is_malicious !== undefined && (
                    <div className={`p-4 rounded-lg border-2 ${
                      result.gemini_ai.is_malicious 
                        ? 'bg-red-950/30 border-red-500/50' 
                        : 'bg-green-950/30 border-green-500/50'
                    }`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          {result.gemini_ai.is_malicious ? (
                            <AlertTriangle className="w-8 h-8 text-red-500" />
                          ) : (
                            <Shield className="w-8 h-8 text-green-500" />
                          )}
                          <div>
                            <div className="text-2xl font-bold text-white">
                              {result.gemini_ai.is_malicious ? '⚠️ MALICIOUS' : '✅ SAFE'}
                            </div>
                            <div className="text-sm text-gray-400 mt-1">
                              AI Prediction: {result.gemini_ai.classification || 'Unknown'}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-3xl font-bold text-white">
                            {result.gemini_ai.ai_threat_score !== undefined 
                              ? result.gemini_ai.ai_threat_score.toFixed(1) 
                              : result.indicator.threat_score.toFixed(1)}
                          </div>
                          <div className="text-xs text-gray-400 mt-1">
                            AI Threat Score
                          </div>
                          <div className={`text-xs mt-1 px-2 py-1 rounded ${
                            result.gemini_ai.confidence === 'High' ? 'bg-green-900/50 text-green-300' :
                            result.gemini_ai.confidence === 'Medium' ? 'bg-yellow-900/50 text-yellow-300' :
                            'bg-gray-900/50 text-gray-300'
                          }`}>
                            {result.gemini_ai.confidence} Confidence
                          </div>
                        </div>
                      </div>
                      {result.gemini_ai.reasoning && (
                        <div className="mt-3 pt-3 border-t border-gray-700/50">
                          <p className="text-sm text-gray-300">
                            <span className="font-semibold text-white">Reasoning: </span>
                            {result.gemini_ai.reasoning}
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* AI Expert Analysis */}
                  {result.gemini_ai.analysis && (
                    <div className="bg-linear-to-br from-blue-950/30 to-cyan-950/30 rounded-lg p-4 border border-blue-900/50">
                      <h4 className="text-blue-300 font-medium mb-2 flex items-center space-x-2">
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                        </svg>
                        <span>Expert Analysis</span>
                      </h4>
                      <p className="text-gray-200 text-sm leading-relaxed">{result.gemini_ai.analysis}</p>
                      {result.gemini_ai.threat_classification && (
                        <div className="mt-3 flex items-center space-x-2">
                          <span className="text-gray-400 text-xs">Classification:</span>
                          <span className="px-2 py-1 bg-blue-900/50 text-blue-300 rounded text-xs font-medium">
                            {result.gemini_ai.threat_classification}
                          </span>
                          {result.gemini_ai.confidence_assessment && (
                            <>
                              <span className="text-gray-600">•</span>
                              <span className="text-gray-400 text-xs">{result.gemini_ai.confidence_assessment}</span>
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Gemini Insights */}
                  {result.gemini_ai.insights && result.gemini_ai.insights.length > 0 && (
                    <div className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                      <h4 className="text-cyan-400 font-medium mb-3 flex items-center space-x-2">
                        <Lightbulb className="w-4 h-4" />
                        <span>AI-Generated Insights</span>
                      </h4>
                      <div className="space-y-2">
                        {result.gemini_ai.insights.map((insight, idx) => (
                          <div key={idx} className="flex items-start space-x-2 text-gray-200">
                            <span className="text-cyan-500 mt-0.5">▸</span>
                            <span className="text-sm">{insight}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Recommendations */}
                  {result.gemini_ai.recommendations && result.gemini_ai.recommendations.length > 0 && (
                    <div className="bg-green-950/20 border border-green-900/50 rounded-lg p-4">
                      <h4 className="text-green-400 font-medium mb-3 flex items-center space-x-2">
                        <Shield className="w-4 h-4" />
                        <span>Security Recommendations</span>
                      </h4>
                      <div className="space-y-2">
                        {result.gemini_ai.recommendations.map((rec, idx) => (
                          <div key={idx} className="flex items-start space-x-2 text-gray-200">
                            <span className="text-green-500 mt-0.5">✓</span>
                            <span className="text-sm">{rec}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Tags */}
              {result.tags && result.tags.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-sm font-medium text-gray-400">Tags</h3>
                  <div className="flex flex-wrap gap-2">
                    {result.tags.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 bg-gray-800 text-gray-300 rounded-full text-sm border border-gray-700"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* External Sources */}
              {result.external_references && result.external_references.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-sm font-medium text-gray-400">External References</h3>
                  <div className="space-y-2">
                    {result.external_references.map((ref, idx) => (
                      <a
                        key={idx}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center space-x-2 text-primary-500 hover:text-primary-400 transition-colors"
                      >
                        <ExternalLink className="w-4 h-4" />
                        <span>{ref.source || ref.url}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Additional Notes */}
              {result.notes && (
                <div className="bg-yellow-950/20 border border-yellow-900/50 rounded-lg p-4">
                  <h3 className="text-yellow-400 font-medium mb-2">Additional Information</h3>
                  <p className="text-gray-300">{result.notes}</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Scan;
