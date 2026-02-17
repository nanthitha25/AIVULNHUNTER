'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { api, type ScanResult, type Vulnerability } from '@/lib/api';
import Link from 'next/link';

export default function ScanDetailPage() {
    const params = useParams();
    const router = useRouter();
    const scanId = params.id as string;

    const [scan, setScan] = useState<ScanResult | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (scanId) {
            loadScanDetails();
        }
    }, [scanId]);

    const loadScanDetails = async () => {
        try {
            setLoading(true);
            const data = await api.getScan(scanId);
            setScan(data);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load scan details');
        } finally {
            setLoading(false);
        }
    };

    const getSeverityColor = (severity: string) => {
        const colors = {
            CRITICAL: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
            HIGH: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
            MEDIUM: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
            LOW: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
            INFO: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
        };
        return colors[severity as keyof typeof colors] || colors.INFO;
    };

    const getStatusIcon = (status: string) => {
        const icons = {
            VULNERABLE: '🔴',
            SECURE: '🟢',
            WARNING: '🟡',
            ERROR: '⚠️',
            CHECK_MANUAL: '🔵',
        };
        return icons[status as keyof typeof icons] || '⚪';
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center">
                <div className="text-center">
                    <div className="inline-block animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600"></div>
                    <p className="mt-4 text-gray-600 dark:text-gray-400">Loading scan details...</p>
                </div>
            </div>
        );
    }

    if (error || !scan) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-8">
                <div className="max-w-4xl mx-auto">
                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6">
                        <h2 className="text-xl font-bold text-red-800 dark:text-red-200 mb-2">Error</h2>
                        <p className="text-red-600 dark:text-red-300">{error || 'Scan not found'}</p>
                        <Link href="/scans" className="mt-4 inline-block text-blue-600 hover:text-blue-800">
                            ← Back to Scans
                        </Link>
                    </div>
                </div>
            </div>
        );
    }

    const vulnerableCount = scan.results.filter(r => r.status === 'VULNERABLE').length;
    const secureCount = scan.results.filter(r => r.status === 'SECURE').length;

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-8">
            <div className="max-w-7xl mx-auto">
                {/* Header */}
                <div className="mb-6">
                    <Link href="/scans" className="text-blue-600 hover:text-blue-800 dark:text-blue-400 mb-4 inline-block">
                        ← Back to Scans
                    </Link>
                    <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
                        Scan Details
                    </h1>
                    <p className="text-gray-600 dark:text-gray-400">{scan.target}</p>
                </div>

                {/* Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
                        <div className="text-sm text-gray-500 dark:text-gray-400">Status</div>
                        <div className="text-2xl font-bold text-gray-900 dark:text-white capitalize">{scan.status}</div>
                    </div>
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
                        <div className="text-sm text-gray-500 dark:text-gray-400">Vulnerabilities</div>
                        <div className="text-2xl font-bold text-red-600 dark:text-red-400">{vulnerableCount}</div>
                    </div>
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
                        <div className="text-sm text-gray-500 dark:text-gray-400">Secure</div>
                        <div className="text-2xl font-bold text-green-600 dark:text-green-400">{secureCount}</div>
                    </div>
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
                        <div className="text-sm text-gray-500 dark:text-gray-400">Duration</div>
                        <div className="text-2xl font-bold text-gray-900 dark:text-white">
                            {scan.duration_seconds ? `${scan.duration_seconds}s` : 'N/A'}
                        </div>
                    </div>
                </div>

                {/* Vulnerabilities */}
                <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6">
                    <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
                        Findings ({scan.results.length})
                    </h2>

                    <div className="space-y-4">
                        {scan.results.map((vuln, index) => (
                            <div
                                key={index}
                                className="border border-gray-200 dark:border-gray-700 rounded-lg p-6 hover:shadow-md transition-shadow"
                            >
                                <div className="flex items-start justify-between mb-4">
                                    <div className="flex-1">
                                        <div className="flex items-center gap-3 mb-2">
                                            <span className="text-2xl">{getStatusIcon(vuln.status)}</span>
                                            <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                                                {vuln.name}
                                            </h3>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                                                {vuln.severity}
                                            </span>
                                            <span className="text-sm text-gray-600 dark:text-gray-400">
                                                {vuln.owasp}
                                            </span>
                                            <span className="text-sm text-gray-600 dark:text-gray-400">
                                                Confidence: {(vuln.confidence * 100).toFixed(0)}%
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                {vuln.explanation && (
                                    <div className="mb-4">
                                        <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Explanation</h4>
                                        <p className="text-gray-700 dark:text-gray-300">{vuln.explanation}</p>
                                    </div>
                                )}

                                {vuln.evidence && (
                                    <div className="mb-4">
                                        <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Evidence</h4>
                                        <pre className="bg-gray-100 dark:bg-gray-900 p-4 rounded-lg text-sm overflow-x-auto">
                                            <code className="text-gray-800 dark:text-gray-200">{vuln.evidence}</code>
                                        </pre>
                                    </div>
                                )}

                                {vuln.mitigation && (
                                    <div>
                                        <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Mitigation</h4>
                                        <p className="text-gray-700 dark:text-gray-300">{vuln.mitigation}</p>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
