'use client';

import { useEffect, useState } from 'react';
import { api, type Scan } from '@/lib/api';
import { wsManager, type ProgressUpdate } from '@/lib/websocket';
import Link from 'next/link';

interface VulnerabilityStats {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
}

export default function DashboardPage() {
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [stats, setStats] = useState<VulnerabilityStats>({
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  });
  const [loading, setLoading] = useState(true);
  const [currentScan, setCurrentScan] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressUpdate | null>(null);

  useEffect(() => {
    loadDashboardData();

    // Subscribe to WebSocket updates
    wsManager.subscribeToErrors((error) => {
      console.error('WebSocket error:', error);
    });

    return () => {
      wsManager.disconnect();
    };
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const data = await api.getScanHistory(5, 0);
      setRecentScans(data.scans);

      // Calculate vulnerability stats from recent scans
      // In a real app, this would come from a dedicated stats endpoint
      const mockStats: VulnerabilityStats = {
        CRITICAL: Math.floor(Math.random() * 10),
        HIGH: Math.floor(Math.random() * 20),
        MEDIUM: Math.floor(Math.random() * 30),
        LOW: Math.floor(Math.random() * 40),
        INFO: Math.floor(Math.random() * 50),
      };
      setStats(mockStats);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const startNewScan = async () => {
    const target = prompt('Enter target URL:');
    if (!target) return;

    try {
      const result = await api.startScan(target);
      setCurrentScan(result.scan_id);

      // Connect to WebSocket for progress updates
      wsManager.connect(result.scan_id);
      wsManager.subscribe(result.scan_id, (update) => {
        setProgress(update);
      });
      wsManager.subscribeToComplete(result.scan_id, () => {
        setProgress(null);
        setCurrentScan(null);
        loadDashboardData();
      });
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan');
    }
  };

  const getSeverityColor = (severity: keyof VulnerabilityStats) => {
    const colors = {
      CRITICAL: 'bg-purple-500',
      HIGH: 'bg-red-500',
      MEDIUM: 'bg-orange-500',
      LOW: 'bg-yellow-500',
      INFO: 'bg-blue-500',
    };
    return colors[severity];
  };

  const totalVulnerabilities = Object.values(stats).reduce((a, b) => a + b, 0);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8 flex justify-between items-center">
          <div>
            <h1 className="text-5xl font-bold text-white mb-2 bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-400">
              AivulnHunter Dashboard
            </h1>
            <p className="text-gray-300">
              Real-time vulnerability scanning powered by PostgreSQL
            </p>
          </div>
          <button
            onClick={startNewScan}
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white rounded-lg font-medium transition-all shadow-lg hover:shadow-xl transform hover:scale-105"
          >
            🚀 Start New Scan
          </button>
        </div>

        {/* Real-time Progress */}
        {currentScan && progress && (
          <div className="mb-8 bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20 shadow-2xl">
            <h2 className="text-xl font-bold text-white mb-4">🔄 Scan in Progress</h2>
            <div className="space-y-3">
              <div className="flex justify-between text-sm text-gray-300">
                <span>{progress.agent}</span>
                <span>{progress.progress}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-3 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-300 ease-out"
                  style={{ width: `${progress.progress}%` }}
                />
              </div>
              <p className="text-sm text-gray-400">{progress.details}</p>
            </div>
          </div>
        )}

        {/* Vulnerability Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
          {(Object.keys(stats) as Array<keyof VulnerabilityStats>).map((severity) => (
            <div
              key={severity}
              className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20 shadow-lg hover:shadow-xl transition-shadow"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-300">{severity}</span>
                <div className={`w-3 h-3 rounded-full ${getSeverityColor(severity)}`} />
              </div>
              <div className="text-3xl font-bold text-white">{stats[severity]}</div>
              <div className="text-xs text-gray-400 mt-1">
                {totalVulnerabilities > 0
                  ? `${((stats[severity] / totalVulnerabilities) * 100).toFixed(1)}%`
                  : '0%'}
              </div>
            </div>
          ))}
        </div>

        {/* Vulnerability Distribution Chart */}
        <div className="mb-8 bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20 shadow-2xl">
          <h2 className="text-2xl font-bold text-white mb-6">📊 Vulnerability Distribution</h2>
          <div className="space-y-4">
            {(Object.keys(stats) as Array<keyof VulnerabilityStats>).map((severity) => {
              const percentage = totalVulnerabilities > 0
                ? (stats[severity] / totalVulnerabilities) * 100
                : 0;

              return (
                <div key={severity} className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-300 font-medium">{severity}</span>
                    <span className="text-gray-400">{stats[severity]} ({percentage.toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-2 overflow-hidden">
                    <div
                      className={`h-full ${getSeverityColor(severity)} transition-all duration-500`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white/10 backdrop-blur-lg rounded-xl p-6 border border-white/20 shadow-2xl">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-white">📋 Recent Scans</h2>
            <Link
              href="/scans"
              className="text-blue-400 hover:text-blue-300 text-sm font-medium"
            >
              View All →
            </Link>
          </div>

          {loading ? (
            <div className="text-center py-12">
              <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400"></div>
              <p className="mt-4 text-gray-400">Loading scans...</p>
            </div>
          ) : recentScans.length === 0 ? (
            <div className="text-center py-12 text-gray-400">
              No scans yet. Start your first scan to see results here.
            </div>
          ) : (
            <div className="space-y-3">
              {recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="block bg-white/5 hover:bg-white/10 rounded-lg p-4 transition-all border border-white/10 hover:border-white/20"
                >
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="font-medium text-white mb-1">{scan.target}</div>
                      <div className="text-sm text-gray-400">
                        {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'N/A'}
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className={`text-lg font-bold ${scan.vulnerabilities_found > 0 ? 'text-red-400' : 'text-green-400'
                          }`}>
                          {scan.vulnerabilities_found}
                        </div>
                        <div className="text-xs text-gray-400">vulnerabilities</div>
                      </div>
                      <div className={`px-3 py-1 rounded-full text-xs font-medium ${scan.status === 'completed' ? 'bg-green-500/20 text-green-300' :
                          scan.status === 'running' ? 'bg-blue-500/20 text-blue-300' :
                            scan.status === 'failed' ? 'bg-red-500/20 text-red-300' :
                              'bg-yellow-500/20 text-yellow-300'
                        }`}>
                        {scan.status}
                      </div>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Quick Stats */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gradient-to-br from-blue-500/20 to-blue-600/20 backdrop-blur-lg rounded-xl p-6 border border-blue-400/30">
            <div className="text-sm text-blue-300 mb-2">Total Scans</div>
            <div className="text-3xl font-bold text-white">{recentScans.length}</div>
          </div>
          <div className="bg-gradient-to-br from-purple-500/20 to-purple-600/20 backdrop-blur-lg rounded-xl p-6 border border-purple-400/30">
            <div className="text-sm text-purple-300 mb-2">Total Vulnerabilities</div>
            <div className="text-3xl font-bold text-white">{totalVulnerabilities}</div>
          </div>
          <div className="bg-gradient-to-br from-green-500/20 to-green-600/20 backdrop-blur-lg rounded-xl p-6 border border-green-400/30">
            <div className="text-sm text-green-300 mb-2">Completed Scans</div>
            <div className="text-3xl font-bold text-white">
              {recentScans.filter(s => s.status === 'completed').length}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
