import { Shield, AlertTriangle, Activity, TrendingUp, TrendingDown } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '../api/client';

const Dashboard = () => {
  // Fetch real data from API with more frequent updates
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: dashboardApi.getStats,
    refetchInterval: 10000, // Refetch every 10 seconds for real-time feel
  });

  const { data: recentThreats } = useQuery({
    queryKey: ['recent-threats'],
    queryFn: () => dashboardApi.getRecentThreats(5),
    refetchInterval: 10000,
  });

  const { data: recentlyAnalyzed } = useQuery({
    queryKey: ['recently-analyzed'],
    queryFn: () => dashboardApi.getRecentlyAnalyzed(8),
    refetchInterval: 5000, // Update every 5 seconds for real-time tracking
  });

  const { data: riskDistributionData } = useQuery({
    queryKey: ['risk-distribution'],
    queryFn: dashboardApi.getRiskDistribution,
    refetchInterval: 30000,
  });

  // Transform data for charts
  const riskDistribution = riskDistributionData?.map((item) => ({
    name: item.risk_level.charAt(0).toUpperCase() + item.risk_level.slice(1),
    value: item.count,
    color: item.risk_level === 'critical' ? '#dc2626' 
         : item.risk_level === 'high' ? '#ef4444'
         : item.risk_level === 'medium' ? '#f59e0b'
         : item.risk_level === 'low' ? '#3b82f6'
         : '#10b981'
  })) || [];

  // Stats cards with real data
  const statsCards = [
    {
      title: 'Total Indicators',
      value: stats?.total_indicators || 0,
      change: '+12.5%',
      trend: 'up',
      icon: Shield,
      color: 'text-primary-500',
      bgColor: 'bg-primary-900/20',
    },
    {
      title: 'Malicious Detected',
      value: stats?.malicious_count || 0,
      change: '+8.2%',
      trend: 'up',
      icon: AlertTriangle,
      color: 'text-danger',
      bgColor: 'bg-red-900/20',
    },
    {
      title: 'Active Alerts',
      value: stats?.active_alerts || 0,
      change: '-15.3%',
      trend: 'down',
      icon: Activity,
      color: 'text-warning',
      bgColor: 'bg-yellow-900/20',
    },
    {
      title: 'Critical Threats',
      value: stats?.critical_count || 0,
      change: '+3.1%',
      trend: 'up',
      icon: TrendingUp,
      color: 'text-success',
      bgColor: 'bg-green-900/20',
    },
  ];

  const threatTrendData = [
    { date: 'Nov 1', threats: 120, malicious: 15 },
    { date: 'Nov 2', threats: 145, malicious: 22 },
    { date: 'Nov 3', threats: 132, malicious: 18 },
    { date: 'Nov 4', threats: 178, malicious: 28 },
    { date: 'Nov 5', threats: 165, malicious: 24 },
    { date: 'Nov 6', threats: 198, malicious: 32 },
    { date: 'Nov 7', threats: 185, malicious: 29 },
  ];

  const topThreats = recentThreats?.slice(0, 5) || [];

  const getRiskBadge = (score) => {
    if (score >= 90) return 'badge badge-critical';
    if (score >= 70) return 'badge badge-danger';
    if (score >= 50) return 'badge badge-warning';
    return 'badge badge-success';
  };

  const getRiskLabel = (score) => {
    if (score >= 90) return 'CRITICAL';
    if (score >= 70) return 'HIGH';
    if (score >= 50) return 'MEDIUM';
    return 'LOW';
  };

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-gray-400">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">Real-time threat intelligence overview</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsCards.map((stat, index) => {
          const Icon = stat.icon;
          const TrendIcon = stat.trend === 'up' ? TrendingUp : TrendingDown;
          const trendColor = stat.trend === 'up' ? 'text-success' : 'text-danger';
          
          return (
            <div key={index} className="card card-hover">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-gray-400 text-sm font-medium">{stat.title}</p>
                  <p className="text-3xl font-bold text-white mt-2">{stat.value}</p>
                  <div className="flex items-center mt-2 space-x-1">
                    <TrendIcon className={`w-4 h-4 ${trendColor}`} />
                    <span className={`text-sm font-medium ${trendColor}`}>{stat.change}</span>
                    <span className="text-gray-500 text-sm">vs last week</span>
                  </div>
                </div>
                <div className={`${stat.bgColor} p-3 rounded-lg`}>
                  <Icon className={`w-6 h-6 ${stat.color}`} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Trend Chart */}
        <div className="lg:col-span-2 card">
          <div className="mb-4">
            <h2 className="text-xl font-bold text-white">Threat Detection Trends</h2>
            <p className="text-gray-400 text-sm">Last 7 days analysis</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={threatTrendData}>
              <defs>
                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="date" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#f3f4f6' }}
              />
              <Legend />
              <Area 
                type="monotone" 
                dataKey="threats" 
                stroke="#3b82f6" 
                fillOpacity={1} 
                fill="url(#colorThreats)" 
                name="Total Threats"
              />
              <Area 
                type="monotone" 
                dataKey="malicious" 
                stroke="#ef4444" 
                fillOpacity={1} 
                fill="url(#colorMalicious)" 
                name="Malicious"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Risk Distribution and Recently Analyzed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Pie Chart */}
        <div className="card">
          <div className="mb-4">
            <h2 className="text-xl font-bold text-white">Risk Distribution</h2>
            <p className="text-gray-400 text-sm">Current threats by severity</p>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={riskDistribution}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
              >
                {riskDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #374151', borderRadius: '8px' }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Recently Analyzed Malicious Threats */}
        <div className="card">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                <Activity className="w-5 h-5 text-primary-500" />
                <span>Recently Checked Threats</span>
              </h2>
              <p className="text-gray-400 text-sm">Live activity - malicious indicators scanned</p>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-xs text-green-500">Live</span>
            </div>
          </div>
          
          <div className="space-y-2 max-h-[280px] overflow-y-auto">
            {recentlyAnalyzed && recentlyAnalyzed.length > 0 ? (
              recentlyAnalyzed.map((threat, index) => (
                <div 
                  key={threat.id} 
                  className="p-3 bg-dark-bg rounded-lg border border-gray-700 hover:border-primary-600 transition-all cursor-pointer animate-fadeIn"
                  style={{ animationDelay: `${index * 50}ms` }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-white font-mono text-sm font-medium truncate flex-1">
                      {threat.indicator_value}
                    </span>
                    <span className={`ml-2 px-2 py-0.5 rounded text-xs font-medium ${
                      threat.risk_level === 'critical' ? 'bg-red-900/50 text-red-300' :
                      threat.risk_level === 'high' ? 'bg-red-800/30 text-red-400' :
                      threat.risk_level === 'medium' ? 'bg-yellow-800/30 text-yellow-400' :
                      'bg-blue-800/30 text-blue-400'
                    }`}>
                      {threat.risk_level.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-400 capitalize">
                      {threat.primary_category.replace('_', ' ')} • {threat.indicator_type}
                    </span>
                    <span className="text-gray-500">
                      {new Date(threat.last_analyzed).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-400">
                <Activity className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No recent activity</p>
                <p className="text-xs text-gray-500 mt-1">Scanned threats will appear here</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Threats Table */}
      <div className="card">
        <div className="mb-4">
          <h2 className="text-xl font-bold text-white">Top Threats</h2>
          <p className="text-gray-400 text-sm">Highest risk indicators detected</p>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Indicator</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Risk Score</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Category</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Country</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Alerts</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium text-sm">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {topThreats.map((threat, index) => (
                <tr key={index} className="hover:bg-dark-hover transition-colors">
                  <td className="py-3 px-4">
                    <span className="text-white font-mono text-sm">{threat.indicator_value}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center space-x-2">
                      <span className="text-white font-bold">{threat.threat_score.toFixed(0)}</span>
                      <span className={getRiskBadge(threat.threat_score)}>{getRiskLabel(threat.threat_score)}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-gray-300">{threat.primary_category}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-gray-300">{threat.indicator_type}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="badge badge-warning">Active</span>
                  </td>
                  <td className="py-3 px-4">
                    <button className="text-primary-500 hover:text-primary-400 text-sm font-medium transition-colors">
                      View Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
