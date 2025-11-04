import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { historyApi } from '../api/client';
import { Clock, Filter, Trash2, Search, RefreshCw, TrendingUp, Shield, AlertTriangle, X } from 'lucide-react';

const History = () => {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    risk_level: '',
    indicator_type: '',
    days: 7,
    search: ''
  });
  const [showFilters, setShowFilters] = useState(false);
  
  const queryClient = useQueryClient();

  // Fetch history
  const { data: historyData, isLoading, refetch } = useQuery({
    queryKey: ['history', page, filters],
    queryFn: () => historyApi.getRecent({ page, page_size: 20, ...filters }),
    refetchInterval: 10000, // Auto-refresh every 10s
  });

  // Fetch stats
  const { data: stats } = useQuery({
    queryKey: ['history-stats', filters.days],
    queryFn: () => historyApi.getStats(filters.days),
    refetchInterval: 15000,
  });

  // Delete item mutation
  const deleteMutation = useMutation({
    mutationFn: (id) => historyApi.deleteItem(id),
    onSuccess: () => {
      queryClient.invalidateQueries(['history']);
      queryClient.invalidateQueries(['history-stats']);
    },
  });

  // Clear history mutation
  const clearMutation = useMutation({
    mutationFn: (days) => historyApi.clearHistory(days),
    onSuccess: () => {
      queryClient.invalidateQueries(['history']);
      queryClient.invalidateQueries(['history-stats']);
    },
  });

  const getRiskBadge = (riskLevel) => {
    const badges = {
      critical: 'bg-red-950/50 text-red-300 border border-red-900',
      high: 'bg-orange-900/30 text-orange-400 border border-orange-800',
      medium: 'bg-yellow-900/30 text-yellow-400 border border-yellow-800',
      low: 'bg-blue-900/30 text-blue-400 border border-blue-800',
      safe: 'bg-green-900/30 text-green-400 border border-green-800',
    };
    return badges[riskLevel] || badges.safe;
  };

  const getTypeBadge = (type) => {
    const badges = {
      ip: 'bg-purple-900/30 text-purple-400',
      domain: 'bg-cyan-900/30 text-cyan-400',
      url: 'bg-indigo-900/30 text-indigo-400',
    };
    return badges[type] || badges.ip;
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    
    return date.toLocaleDateString();
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPage(1);
  };

  const handleClearFilters = () => {
    setFilters({
      risk_level: '',
      indicator_type: '',
      days: 7,
      search: ''
    });
    setPage(1);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center space-x-3">
            <Clock className="w-8 h-8 text-primary-500" />
            <span>Scan History</span>
          </h1>
          <p className="text-gray-400 mt-1">Track all your threat intelligence lookups</p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => refetch()}
            className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="px-4 py-2 bg-dark-card border border-gray-700 hover:border-gray-600 text-white rounded-lg flex items-center space-x-2 transition-colors"
          >
            <Filter className="w-4 h-4" />
            <span>Filters</span>
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-dark-card rounded-lg border border-gray-700 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Scans</p>
                <p className="text-3xl font-bold text-white mt-1">{stats.total_scans}</p>
              </div>
              <TrendingUp className="w-10 h-10 text-primary-500" />
            </div>
          </div>
          
          <div className="bg-dark-card rounded-lg border border-gray-700 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Malicious</p>
                <p className="text-3xl font-bold text-red-400 mt-1">{stats.malicious_count}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-red-500" />
            </div>
          </div>
          
          <div className="bg-dark-card rounded-lg border border-gray-700 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Clean</p>
                <p className="text-3xl font-bold text-green-400 mt-1">{stats.clean_count}</p>
              </div>
              <Shield className="w-10 h-10 text-green-500" />
            </div>
          </div>
          
          <div className="bg-dark-card rounded-lg border border-gray-700 p-6">
            <div>
              <p className="text-gray-400 text-sm mb-2">Last {filters.days} days</p>
              <button
                onClick={() => handleFilterChange('days', filters.days === 7 ? 30 : 7)}
                className="text-primary-500 hover:text-primary-400 text-sm transition-colors"
              >
                Switch to {filters.days === 7 ? '30' : '7'} days
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Filters Panel */}
      {showFilters && (
        <div className="bg-dark-card rounded-lg border border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Filters</h3>
            <button
              onClick={handleClearFilters}
              className="text-sm text-gray-400 hover:text-white transition-colors"
            >
              Clear all
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Search */}
            <div>
              <label className="text-sm text-gray-400 mb-2 block">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type="text"
                  placeholder="IP, domain, URL..."
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 placeholder-gray-500 focus:outline-none focus:border-primary-600"
                />
              </div>
            </div>

            {/* Risk Level */}
            <div>
              <label className="text-sm text-gray-400 mb-2 block">Risk Level</label>
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

            {/* Indicator Type */}
            <div>
              <label className="text-sm text-gray-400 mb-2 block">Type</label>
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

            {/* Time Range */}
            <div>
              <label className="text-sm text-gray-400 mb-2 block">Time Range</label>
              <select
                value={filters.days}
                onChange={(e) => handleFilterChange('days', parseInt(e.target.value))}
                className="w-full px-4 py-2 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 focus:outline-none focus:border-primary-600"
              >
                <option value="1">Last 24 hours</option>
                <option value="7">Last 7 days</option>
                <option value="30">Last 30 days</option>
                <option value="90">Last 90 days</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* History Table */}
      <div className="bg-dark-card rounded-lg border border-gray-700 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="w-12 h-12 border-4 border-primary-600 border-t-transparent rounded-full animate-spin"></div>
          </div>
        ) : historyData && historyData.items.length > 0 ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-dark-bg border-b border-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-400">Indicator</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-400">Type</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-400">Threat Score</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-400">Risk Level</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-400">Scanned</th>
                    <th className="px-6 py-4 text-right text-sm font-medium text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {historyData.items.map((item) => (
                    <tr key={item.id} className="hover:bg-dark-bg/50 transition-colors">
                      <td className="px-6 py-4">
                        <div className="flex items-center space-x-3">
                          <div className={`w-2 h-2 rounded-full ${item.is_malicious ? 'bg-red-500' : 'bg-green-500'}`}></div>
                          <span className="text-white font-mono text-sm">{item.indicator_value}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getTypeBadge(item.indicator_type)}`}>
                          {item.indicator_type.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center space-x-2">
                          <div className="w-20 h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${
                                item.threat_score >= 70 ? 'bg-red-500' :
                                item.threat_score >= 40 ? 'bg-yellow-500' :
                                'bg-green-500'
                              }`}
                              style={{ width: `${item.threat_score}%` }}
                            ></div>
                          </div>
                          <span className="text-sm text-gray-300">{item.threat_score.toFixed(0)}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-3 py-1 rounded text-xs font-medium uppercase ${getRiskBadge(item.risk_level)}`}>
                          {item.risk_level}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-400">
                        {formatDate(item.last_analyzed)}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button
                          onClick={() => deleteMutation.mutate(item.id)}
                          className="text-red-400 hover:text-red-300 transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {historyData.pages > 1 && (
              <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-between">
                <div className="text-sm text-gray-400">
                  Page {historyData.page} of {historyData.pages} • {historyData.total} total scans
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-4 py-2 bg-dark-bg border border-gray-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-800 transition-colors"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setPage(p => Math.min(historyData.pages, p + 1))}
                    disabled={page === historyData.pages}
                    className="px-4 py-2 bg-dark-bg border border-gray-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-800 transition-colors"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="flex flex-col items-center justify-center py-20">
            <Clock className="w-16 h-16 text-gray-600 mb-4" />
            <p className="text-gray-400 text-lg">No scan history found</p>
            <p className="text-gray-500 text-sm mt-2">Start scanning indicators to build your history</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default History;
