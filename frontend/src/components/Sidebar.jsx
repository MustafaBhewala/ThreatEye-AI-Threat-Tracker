import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Shield, 
  AlertTriangle, 
  FileText,
  Settings,
  Search,
  Activity,
  Clock
} from 'lucide-react';

const Sidebar = () => {
  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/threats', icon: Shield, label: 'Threats' },
    { to: '/alerts', icon: AlertTriangle, label: 'Alerts' },
    { to: '/scan', icon: Search, label: 'Scan' },
    { to: '/history', icon: Clock, label: 'History' },
    { to: '/activity', icon: Activity, label: 'Activity' },
    { to: '/reports', icon: FileText, label: 'Reports' },
    { to: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-dark-card border-r border-gray-700 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-gray-700">
        <div className="flex items-center space-x-3">
          <div className="bg-primary-600 p-2 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">ThreatEye</h1>
            <p className="text-xs text-gray-400">AI Threat Tracker</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                isActive
                  ? 'bg-primary-600 text-white shadow-lg'
                  : 'text-gray-400 hover:bg-dark-hover hover:text-white'
              }`
            }
          >
            <item.icon className="w-5 h-5" />
            <span className="font-medium">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Status Footer */}
      <div className="p-4 border-t border-gray-700">
        <div className="bg-dark-bg rounded-lg p-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-400">System Status</span>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
              <span className="text-success font-medium">Online</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
