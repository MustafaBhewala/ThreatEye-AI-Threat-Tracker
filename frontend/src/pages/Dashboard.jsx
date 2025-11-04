import { Shield, AlertTriangle, Activity, TrendingUp, TrendingDown } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const Dashboard = () => {
  // Mock data for demonstration
  const stats = [
    {
      title: 'Total Indicators',
      value: '1,247',
      change: '+12.5%',
      trend: 'up',
      icon: Shield,
      color: 'text-primary-500',
      bgColor: 'bg-primary-900/20',
    },
    {
      title: 'Malicious Detected',
      value: '156',
      change: '+8.2%',
      trend: 'up',
      icon: AlertTriangle,
      color: 'text-danger',
      bgColor: 'bg-red-900/20',
    },
    {
      title: 'Active Alerts',
      value: '23',
      change: '-15.3%',
      trend: 'down',
      icon: Activity,
      color: 'text-warning',
      bgColor: 'bg-yellow-900/20',
    },
    {
      title: 'Threat Score Avg',
      value: '42.8',
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

  const riskDistribution = [
    { name: 'Safe', value: 45, color: '#10b981' },
    { name: 'Low', value: 25, color: '#3b82f6' },
    { name: 'Medium', value: 18, color: '#f59e0b' },
    { name: 'High', value: 8, color: '#ef4444' },
    { name: 'Critical', value: 4, color: '#dc2626' },
  ];

  const topThreats = [
    { ip: '192.0.2.100', score: 95, category: 'Botnet', country: 'RU', alerts: 5 },
    { ip: 'evil-site.com', score: 92, category: 'Phishing', country: 'CN', alerts: 4 },
    { ip: '198.51.100.25', score: 88, category: 'Malware', country: 'US', alerts: 3 },
    { ip: '203.0.113.50', score: 85, category: 'C2', country: 'UA', alerts: 3 },
    { ip: 'spam-host.net', score: 82, category: 'Spam', country: 'BR', alerts: 2 },
  ];

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

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">Real-time threat intelligence overview</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => {
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
                    <span className="text-white font-mono text-sm">{threat.ip}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center space-x-2">
                      <span className="text-white font-bold">{threat.score}</span>
                      <span className={getRiskBadge(threat.score)}>{getRiskLabel(threat.score)}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-gray-300">{threat.category}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-gray-300">{threat.country}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="badge badge-warning">{threat.alerts} Active</span>
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
