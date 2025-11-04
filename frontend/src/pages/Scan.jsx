import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { indicatorsApi } from '../api/client';
import { Search, AlertTriangle, Shield, Globe, MapPin, Server, Calendar, Activity, ExternalLink } from 'lucide-react';

const Scan = () => {
  const [searchValue, setSearchValue] = useState('');
  const [result, setResult] = useState(null);

  const searchMutation = useMutation({
    mutationFn: (value) => indicatorsApi.search(value),
    onSuccess: (data) => {
      setResult(data);
    },
    onError: (error) => {
      setResult({ error: true, message: error.message || 'Threat indicator not found in database' });
    },
  });

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchValue.trim()) {
      searchMutation.mutate(searchValue.trim());
    }
  };

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
              placeholder="Enter IP address, domain, or URL..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="w-full pl-12 pr-4 py-4 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 placeholder-gray-500 focus:outline-none focus:border-primary-600 focus:ring-2 focus:ring-primary-600 text-lg"
            />
          </div>
          <button
            type="submit"
            disabled={searchMutation.isPending}
            className="w-full py-4 bg-primary-600 hover:bg-primary-700 text-white rounded-lg font-medium text-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {searchMutation.isPending ? 'Searching...' : 'Search Database'}
          </button>
        </form>

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
              {result.enrichments && result.enrichments.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                    <Globe className="w-5 h-5" />
                    <span>Enrichment Data</span>
                  </h3>
                  {result.enrichments.map((enrichment, idx) => (
                    <div key={idx} className="bg-dark-bg rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-primary-500 font-medium">{enrichment.source}</span>
                        <span className="text-gray-400 text-sm">{new Date(enrichment.retrieved_at).toLocaleString()}</span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                        {enrichment.geo_country && (
                          <div>
                            <div className="flex items-center space-x-2 mb-1">
                              <MapPin className="w-4 h-4 text-gray-400" />
                              <span className="text-gray-400 text-sm">Location</span>
                            </div>
                            <div className="text-white">{enrichment.geo_country}</div>
                          </div>
                        )}
                        {enrichment.asn && (
                          <div>
                            <div className="flex items-center space-x-2 mb-1">
                              <Server className="w-4 h-4 text-gray-400" />
                              <span className="text-gray-400 text-sm">ASN</span>
                            </div>
                            <div className="text-white">{enrichment.asn}</div>
                          </div>
                        )}
                        {enrichment.org && (
                          <div>
                            <div className="flex items-center space-x-2 mb-1">
                              <Server className="w-4 h-4 text-gray-400" />
                              <span className="text-gray-400 text-sm">Organization</span>
                            </div>
                            <div className="text-white">{enrichment.org}</div>
                          </div>
                        )}
                      </div>
                      {enrichment.abuse_contacts && enrichment.abuse_contacts.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-gray-700">
                          <span className="text-gray-400 text-sm">Abuse Contacts: </span>
                          <span className="text-white">{enrichment.abuse_contacts.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  ))}
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
