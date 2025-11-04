/**
 * API Client for ThreatEye Backend
 * Centralized API communication layer
 */

import axios from 'axios';

// API Base URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// ============================================
// Dashboard APIs
// ============================================

export const dashboardApi = {
  getStats: () => apiClient.get('/api/dashboard/stats'),
  getRecentThreats: (limit = 10) => apiClient.get(`/api/dashboard/recent-threats?limit=${limit}`),
  getThreatTimeline: (days = 7) => apiClient.get(`/api/dashboard/threat-timeline?days=${days}`),
  getRiskDistribution: () => apiClient.get('/api/dashboard/risk-distribution'),
  getThreatCategories: () => apiClient.get('/api/dashboard/threat-categories'),
  getGeographicDistribution: () => apiClient.get('/api/dashboard/geographic-distribution'),
  getTopAsns: (limit = 10) => apiClient.get(`/api/dashboard/top-asns?limit=${limit}`),
  getRecentAlerts: (limit = 5) => apiClient.get(`/api/dashboard/recent-alerts?limit=${limit}`),
  getRecentlyAnalyzed: (limit = 10) => apiClient.get(`/api/dashboard/recently-analyzed?limit=${limit}`),
  getThreatTrends: (days = 7) => apiClient.get(`/api/dashboard/threat-trends?days=${days}`),
  getTopMaliciousIPs: (limit = 10) => apiClient.get(`/api/dashboard/top-malicious-ips?limit=${limit}`),
  getTopMaliciousDomains: (limit = 10) => apiClient.get(`/api/dashboard/top-malicious-domains?limit=${limit}`),
  getLiveStats: () => apiClient.get('/api/dashboard/live-stats'),
};

// ============================================
// Indicators APIs
// ============================================

export const indicatorsApi = {
  getAll: (params = {}) => {
    // Filter out null, undefined, and empty string values
    const cleanParams = Object.entries(params).reduce((acc, [key, value]) => {
      if (value !== null && value !== undefined && value !== '') {
        acc[key] = value;
      }
      return acc;
    }, {});
    
    const queryParams = new URLSearchParams(cleanParams).toString();
    return apiClient.get(`/api/indicators/?${queryParams}`);
  },
  
  getById: (id) => apiClient.get(`/api/indicators/${id}`),
  
  search: (value) => apiClient.get(`/api/indicators/search/${value}`),
  
  getSummary: () => apiClient.get('/api/indicators/stats/summary'),
};

// ============================================
// Scan APIs
// ============================================

export const scanApi = {
  liveScan: (indicatorValue) => apiClient.post('/api/scan/live', null, {
    params: { indicator_value: indicatorValue }
  }),
};

// ============================================
// History APIs
// ============================================

export const historyApi = {
  getRecent: (params = {}) => {
    const queryParams = new URLSearchParams(params).toString();
    return apiClient.get(`/api/history/recent?${queryParams}`);
  },
  getStats: (days = 7) => apiClient.get(`/api/history/stats?days=${days}`),
  deleteItem: (id) => apiClient.delete(`/api/history/${id}`),
  clearHistory: (days = null) => {
    const params = days ? `?days=${days}` : '';
    return apiClient.delete(`/api/history/clear${params}`);
  },
};

// ============================================
// Alerts APIs (to be implemented)
// ============================================

export const alertsApi = {
  getAll: () => apiClient.get('/api/alerts'),
  getById: (id) => apiClient.get(`/api/alerts/${id}`),
  acknowledge: (id) => apiClient.put(`/api/alerts/${id}/acknowledge`),
  resolve: (id) => apiClient.put(`/api/alerts/${id}/resolve`),
};

// ============================================
// Health Check
// ============================================

export const healthCheck = () => apiClient.get('/health');

export default apiClient;
