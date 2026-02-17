'use client';

import { useEffect, useState } from 'react';
import { api, type Scan } from '@/lib/api';
import Link from 'next/link';

export default function ScansPage() {
    const [scans, setScans] = useState<Scan[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filter, setFilter] = useState<string>('');

    useEffect(() => {
        loadScans();
    }, [filter]);

    const loadScans = async () => {
        try {
            setLoading(true);
            const data = await api.getScanHistory(20, 0, filter || undefined);
            setScans(data.scans);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load scans');
        } finally {
            setLoading(false);
        }
    };

    const getStatusBadge = (status: string) => {
        const colors = {
            completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
            running: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
            pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
            failed: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
            cancelled: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
        };

        return (
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${colors[status as keyof typeof colors] || colors.pending}`}>
                {status}
            </span>
        );
    };

    const formatDate = (dateString: string | null) => {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleString();
    };

    const formatDuration = (seconds: number | null) => {
        if (!seconds) return 'N/A';
        if (seconds < 60) return `${seconds}s`;
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${minutes}m ${secs}s`;
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-8">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="mb-8">
                    <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
                        Scan History
                    </h1>
                    <p className="text-gray-600 dark:text-gray-400">
                        View all vulnerability scans from PostgreSQL database
                    </p>
                </div>

                {/* Filters */}
                <div className="mb-6 flex gap-4">
                    <select
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    >
                        <option value="">All Statuses</option>
                        <option value="completed">Completed</option>
                        <option value="running">Running</option>
                        <option value="pending">Pending</option>
                        <option value="failed">Failed</option>
                    </select>

                    <button
                        onClick={loadScans}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
                    >
                        Refresh
                    </button>
                </div>

                {/* Loading State */}
                {loading && (
                    <div className="text-center py-12">
                        <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                        <p className="mt-4 text-gray-600 dark:text-gray-400">Loading scans...</p>
                    </div>
                )}

                {/* Error State */}
                {error && (
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
                        <p className="text-red-800 dark:text-red-200">Error: {error}</p>
                    </div>
                )}

                {/* Scans Table */}
                {!loading && !error && (
                    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead className="bg-gray-50 dark:bg-gray-700">
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                            Target
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                            Status
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                            Vulnerabilities
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                            Duration
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                            Started
                                        </th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                                            Actions
                                        </th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                                    {scans.length === 0 ? (
                                        <tr>
                                            <td colSpan={6} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                                                No scans found. Start a new scan to see results here.
                                            </td>
                                        </tr>
                                    ) : (
                                        scans.map((scan) => (
                                            <tr key={scan.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                                                        {scan.target}
                                                    </div>
                                                    <div className="text-xs text-gray-500 dark:text-gray-400">
                                                        {scan.scan_type}
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    {getStatusBadge(scan.status)}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <div className="flex items-center gap-2">
                                                        <span className={`text-lg font-bold ${scan.vulnerabilities_found > 0
                                                                ? 'text-red-600 dark:text-red-400'
                                                                : 'text-green-600 dark:text-green-400'
                                                            }`}>
                                                            {scan.vulnerabilities_found}
                                                        </span>
                                                        <span className="text-xs text-gray-500 dark:text-gray-400">
                                                            / {scan.total_rules_tested} tests
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                                                    {formatDuration(scan.duration_seconds)}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                                    {formatDate(scan.started_at)}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm">
                                                    <Link
                                                        href={`/scans/${scan.id}`}
                                                        className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium"
                                                    >
                                                        View Details →
                                                    </Link>
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {/* Stats Summary */}
                {!loading && !error && scans.length > 0 && (
                    <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                            <div className="text-sm text-gray-500 dark:text-gray-400">Total Scans</div>
                            <div className="text-2xl font-bold text-gray-900 dark:text-white">{scans.length}</div>
                        </div>
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                            <div className="text-sm text-gray-500 dark:text-gray-400">Completed</div>
                            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                                {scans.filter(s => s.status === 'completed').length}
                            </div>
                        </div>
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                            <div className="text-sm text-gray-500 dark:text-gray-400">Running</div>
                            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                                {scans.filter(s => s.status === 'running').length}
                            </div>
                        </div>
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
                            <div className="text-sm text-gray-500 dark:text-gray-400">Total Vulnerabilities</div>
                            <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                                {scans.reduce((sum, s) => sum + s.vulnerabilities_found, 0)}
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
