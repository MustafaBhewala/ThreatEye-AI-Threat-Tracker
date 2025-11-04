import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { indicatorsApi } from '../api/client';
import { Search, Filter, Download, Eye, AlertTriangle, Shield } from 'lucide-react';

const Threats = () => {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState({
    risk_level: '',
    indicator_type: '',
    is_malicious: null,
  });

  // Fetch threats with pagination and filters
  const { data, isLoading, error } = useQuery({
    queryKey: ['threats', page, pageSize, filters, searchQuery],
    queryFn: () => {
      const params = {
        page,
        page_size: pageSize,
      };
      
      // Only add filters if they have values
      if (searchQuery) params.search = searchQuery;
      if (filters.risk_level) params.risk_level = filters.risk_level;
      if (filters.indicator_type) params.indicator_type = filters.indicator_type;
      if (filters.is_malicious !== null && filters.is_malicious !== undefined && filters.is_malicious !== '') {
        params.is_malicious = filters.is_malicious;
      }
      
      return indicatorsApi.getAll(params);
    },
    refetchInterval: 30000,
  });

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(1);
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value === '' ? null : value
    }));
    setPage(1);
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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">Threat Indicators</h1>
          <p className="text-gray-400">Monitor and analyze malicious IPs, domains, and URLs</p>
        </div>
        <button className="flex items-center space-x-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg transition-colors">
          <Download className="w-4 h-4" />
          <span>Export CSV</span>
        </button>
      </div>

      {/* Search and Filters */}
      <div className="bg-dark-card rounded-lg border border-gray-700 p-6">
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="flex gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search by IP, domain, or URL..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 placeholder-gray-500 focus:outline-none focus:border-primary-600 focus:ring-1 focus:ring-primary-600"
              />
            </div>
            <button
              type="submit"
              className="px-6 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg transition-colors"
            >
              Search
            </button>
          </div>

          <div className="flex gap-4">
            <div className="flex-1">
              <label className="block text-gray-400 text-sm mb-2">Risk Level</label>
              <select
                value={filters.risk_level}
                onChange={(e) => handleFilterChange('risk_level', e.target.value)}
                className="w-full px-4 py-2 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 focus:outline-none focus:border-primary-600"
              >
                <option value="">All Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="safe">Safe</option>
              </select>
            </div>

            <div className="flex-1">
              <label className="block text-gray-400 text-sm mb-2">Type</label>
              <select
                value={filters.indicator_type}
                onChange={(e) => handleFilterChange('indicator_type', e.target.value)}
                className="w-full px-4 py-2 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 focus:outline-none focus:border-primary-600"
              >
                <option value="">All Types</option>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
              </select>
            </div>

            <div className="flex-1">
              <label className="block text-gray-400 text-sm mb-2">Status</label>
              <select
                value={filters.is_malicious === null ? '' : filters.is_malicious}
                onChange={(e) => handleFilterChange('is_malicious', e.target.value === '' ? null : e.target.value === 'true')}
                className="w-full px-4 py-2 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 focus:outline-none focus:border-primary-600"
              >
                <option value="">All Status</option>
                <option value="true">Malicious</option>
                <option value="false">Safe</option>
              </select>
            </div>
          </div>
        </form>
      </div>

      {/* Results Summary */}
      {data && (
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>
            Showing {((page - 1) * pageSize) + 1} to {Math.min(page * pageSize, data.total)} of {data.total} threats
          </span>
          <span>Page {page} of {data.total_pages}</span>
        </div>
      )}

      {/* Threats Table */}
      <div className="bg-dark-card rounded-lg border border-gray-700 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-96">
            <div className="text-gray-400">Loading threats...</div>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-96">
            <div className="text-red-400">Error loading threats</div>
          </div>
        ) : data && data.data.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-dark-bg">
                <tr>
                  <th className="text-left py-4 px-6 text-gray-400 font-medium text-sm">Indicator</th>
                  <th className="text-left py-4 px-6 text-gray-400 font-medium text-sm">Type</th>
                  <th className="text-left py-4 px-6 text-gray-400 font-medium text-sm">Risk</th>
                  <th className="text-left py-4 px-6 text-gray-400 font-medium text-sm">Score</th>
                  <th className="text-left py-4 px-6 text-gray-400 font-medium text-sm">Category</th>
                  <th className="text-left py-4 px-6 text-gray-400 font-medium text-sm">Last Seen</th>
                  <th className="text-left py-4 px-6 text-gray-400 font-medium text-sm">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {data.data.map((threat) => (
                  <tr key={threat.id} className="hover:bg-dark-hover transition-colors">
                    <td className="py-4 px-6">
                      <div className="flex items-center space-x-2">
                        {threat.is_malicious ? (
                          <AlertTriangle className="w-4 h-4 text-red-400" />
                        ) : (
                          <Shield className="w-4 h-4 text-green-400" />
                        )}
                        <span className="text-white font-mono text-sm">{threat.indicator_value}</span>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTypeBadge(threat.indicator_type)}`}>
                        {threat.indicator_type.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRiskBadge(threat.risk_level)}`}>
                        {threat.risk_level.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-white font-bold">{threat.threat_score.toFixed(1)}</span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-gray-300 capitalize">{threat.primary_category.replace('_', ' ')}</span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-gray-400 text-sm">
                        {new Date(threat.last_seen).toLocaleDateString()}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <button className="flex items-center space-x-1 text-primary-500 hover:text-primary-400 text-sm font-medium transition-colors">
                        <Eye className="w-4 h-4" />
                        <span>Details</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-96 text-gray-400">
            <Shield className="w-16 h-16 mb-4 opacity-50" />
            <p className="text-lg">No threats found</p>
            <p className="text-sm">Try adjusting your search or filters</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {data && data.total_pages > 1 && (
        <div className="flex items-center justify-center space-x-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 bg-dark-card border border-gray-700 rounded-lg text-gray-300 hover:bg-dark-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Previous
          </button>
          
          <div className="flex items-center space-x-2">
            {[...Array(Math.min(5, data.total_pages))].map((_, idx) => {
              const pageNum = idx + 1;
              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={`w-10 h-10 rounded-lg transition-colors ${
                    page === pageNum
                      ? 'bg-primary-600 text-white'
                      : 'bg-dark-card border border-gray-700 text-gray-300 hover:bg-dark-hover'
                  }`}
                >
                  {pageNum}
                </button>
              );
            })}
          </div>

          <button
            onClick={() => setPage(p => Math.min(data.total_pages, p + 1))}
            disabled={page === data.total_pages}
            className="px-4 py-2 bg-dark-card border border-gray-700 rounded-lg text-gray-300 hover:bg-dark-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

export default Threats;
