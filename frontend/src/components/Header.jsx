import { Bell, User, Search as SearchIcon } from 'lucide-react';
import { useState } from 'react';

const Header = () => {
  const [notifications] = useState(3);

  return (
    <header className="fixed top-0 right-0 left-64 h-16 bg-dark-card/80 backdrop-blur-md border-b border-gray-700/50 shadow-lg z-10">
      <div className="h-full px-6 flex items-center justify-between">
        {/* Search Bar */}
        <div className="flex-1 max-w-2xl">
          <div className="relative">
            <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search IPs, domains, or threats..."
              className="w-full pl-10 pr-4 py-2 bg-dark-bg border border-gray-700 rounded-lg text-gray-300 placeholder-gray-500 focus:outline-none focus:border-primary-600 focus:ring-1 focus:ring-primary-600 transition-all"
            />
          </div>
        </div>

        {/* Right Section */}
        <div className="flex items-center space-x-4">
          {/* Notifications */}
          <button className="relative p-2 text-gray-400 hover:text-white hover:bg-dark-hover rounded-lg transition-all">
            <Bell className="w-5 h-5" />
            {notifications > 0 && (
              <span className="absolute -top-1 -right-1 w-5 h-5 bg-danger text-white text-xs rounded-full flex items-center justify-center font-medium">
                {notifications}
              </span>
            )}
          </button>

          {/* User Menu */}
          <div className="flex items-center space-x-3 px-3 py-2 hover:bg-dark-hover rounded-lg cursor-pointer transition-all">
            <div className="w-8 h-8 bg-primary-600 rounded-full flex items-center justify-center">
              <User className="w-5 h-5 text-white" />
            </div>
            <div className="text-sm">
              <p className="text-white font-medium">Admin</p>
              <p className="text-gray-400 text-xs">Security Analyst</p>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
