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
    const [downloadingPDF, setDownloadingPDF] = useState(false);
    const [pdfError, setPdfError] = useState<string | null>(null);

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

    const downloadPDF = async () => {
        if (!scan) return;
        setDownloadingPDF(true);
        setPdfError(null);
        try {
            const { default: jsPDF } = await import('jspdf');
            const { default: autoTable } = await import('jspdf-autotable');

            const doc = new jsPDF();
            const pageWidth = doc.internal.pageSize.getWidth();

            // Header - White Theme
            doc.setFillColor(255, 255, 255);
            doc.rect(0, 0, pageWidth, 40, 'F');
            
            doc.setTextColor(40, 40, 40);
            doc.setFontSize(22);
            doc.setFont('helvetica', 'bold');
            doc.text('AivulnHunter Security Audit', 14, 22);
            
            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(100, 100, 100);
            doc.text(`Target: ${scan.target}`, 14, 30);
            doc.text(`Date: ${new Date().toLocaleString()}`, 14, 35);
            
            doc.setDrawColor(200, 200, 200);
            doc.line(14, 40, pageWidth - 14, 40);

            // Summary Section
            doc.setFontSize(16);
            doc.setTextColor(0, 0, 0);
            doc.text('1. Scan Summary', 14, 55);
            
            const summaryData = [
                ['Status', scan.status.toUpperCase()],
                ['Total Findings', scan.results.length.toString()],
                ['Vulnerabilities', scan.results.filter(r => r.status === 'VULNERABLE').length.toString()],
                ['Secure Checks', scan.results.filter(r => r.status === 'SECURE').length.toString()],
                ['Duration', `${scan.duration_seconds || 0} seconds`]
            ];

            autoTable(doc, {
                startY: 60,
                head: [['Metric', 'Value']],
                body: summaryData,
                theme: 'striped',
                headStyles: { fillColor: [100, 100, 100] as any },
            });

            // Vulnerabilities Section
            doc.setFontSize(16);
            doc.text('2. Detected Vulnerabilities', 14, (doc as any).lastAutoTable.finalY + 15);
            
            const vulnerabilities = scan.results.filter(r => r.status === 'VULNERABLE');
            
            if (vulnerabilities.length > 0) {
                const tableData = vulnerabilities.map(v => [
                    v.name,
                    v.severity,
                    v.owasp,
                    `${(v.confidence * 100).toFixed(0)}%`
                ]);

                autoTable(doc, {
                    startY: (doc as any).lastAutoTable.finalY + 20,
                    head: [['Vulnerability', 'Severity', 'OWASP ID', 'Confidence']],
                    body: tableData,
                    theme: 'grid',
                    headStyles: { fillColor: [180, 0, 0] },
                });
            } else {
                doc.setFontSize(10);
                doc.text('No critical vulnerabilities detected in this scan.', 14, (doc as any).lastAutoTable.finalY + 25);
            }

            // Detailed Findings
            let yPos = (doc as any).lastAutoTable.finalY + 20;
            vulnerabilities.forEach((vuln, index) => {
                if (yPos > 250) {
                    doc.addPage();
                    yPos = 20;
                }
                
                doc.setFontSize(14);
                doc.setFont('helvetica', 'bold');
                doc.text(`${index + 1}. ${vuln.name}`, 14, yPos);
                yPos += 7;
                
                doc.setFontSize(10);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(80, 80, 80);
                
                const explanationLines = doc.splitTextToSize(`Explanation: ${vuln.explanation}`, pageWidth - 28);
                doc.text(explanationLines, 14, yPos);
                yPos += (explanationLines.length * 5) + 5;

                const mitigationLines = doc.splitTextToSize(`Mitigation: ${vuln.mitigation}`, pageWidth - 28);
                doc.text(mitigationLines, 14, yPos);
                yPos += (mitigationLines.length * 5) + 10;
            });

            // Footer
            const pageCount = (doc as any).internal.getNumberOfPages();
            for (let i = 1; i <= pageCount; i++) {
                doc.setPage(i);
                doc.setFontSize(8);
                doc.setTextColor(150, 150, 150);
                doc.text(`AivulnHunter Security Report - Page ${i} of ${pageCount}`, pageWidth / 2, 285, { align: 'center' });
            }

            doc.save(`aivulnhunter_scan_${scanId.slice(0, 8)}.pdf`);
        } catch (err) {
            console.error('PDF Generation Error:', err);
            setPdfError(err instanceof Error ? err.message : 'PDF generation failed');
        } finally {
            setDownloadingPDF(false);
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

    const getSeverityBorderColor = (severity: string) => {
        const colors: Record<string, string> = {
            CRITICAL: 'border-l-purple-500',
            HIGH: 'border-l-red-500',
            MEDIUM: 'border-l-orange-400',
            LOW: 'border-l-yellow-400',
            INFO: 'border-l-blue-400',
        };
        return colors[severity] || 'border-l-gray-400';
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

    // Format multiline text with line breaks preserved
    const renderMultiline = (text: string) =>
        text.split('\n').map((line, i) => (
            <span key={i}>
                {line}
                {i < text.split('\n').length - 1 && <br />}
            </span>
        ));

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
                <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
                    <div>
                        <Link href="/scans" className="text-blue-600 hover:text-blue-800 dark:text-blue-400 mb-4 inline-block">
                            ← Back to Scans
                        </Link>
                        <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
                            Scan Details
                        </h1>
                        <p className="text-gray-600 dark:text-gray-400">{scan.target}</p>
                    </div>

                    {/* PDF Download Button */}
                    <div className="flex flex-col items-end gap-2">
                        <button
                            id="download-pdf-btn"
                            onClick={downloadPDF}
                            disabled={downloadingPDF || scan.status !== 'completed'}
                            className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-white transition-all shadow-md
                                ${scan.status !== 'completed'
                                    ? 'bg-gray-400 cursor-not-allowed opacity-60'
                                    : downloadingPDF
                                        ? 'bg-red-400 cursor-wait'
                                        : 'bg-red-600 hover:bg-red-700 active:scale-95'
                                }`}
                        >
                            {downloadingPDF ? (
                                <>
                                    <span className="inline-block animate-spin rounded-full h-4 w-4 border-b-2 border-white"></span>
                                    Generating PDF…
                                </>
                            ) : (
                                <>
                                    📄 Download Professional PDF
                                </>
                            )}
                        </button>
                        {scan.status !== 'completed' && (
                            <p className="text-xs text-gray-500 dark:text-gray-400">Available when scan completes</p>
                        )}
                        {pdfError && (
                            <p className="text-xs text-red-600 dark:text-red-400">{pdfError}</p>
                        )}
                    </div>
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

                    <div className="space-y-6">
                        {scan.results.map((vuln, index) => (
                            <div
                                key={index}
                                className={`border border-gray-200 dark:border-gray-700 border-l-4 ${getSeverityBorderColor(vuln.severity)} rounded-lg p-6 hover:shadow-md transition-shadow`}
                            >
                                {/* Finding header */}
                                <div className="flex items-start justify-between mb-4">
                                    <div className="flex-1">
                                        <div className="flex items-center gap-3 mb-2">
                                            <span className="text-2xl">{getStatusIcon(vuln.status)}</span>
                                            <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                                                {vuln.name}
                                            </h3>
                                        </div>
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(vuln.severity)}`}>
                                                {vuln.severity}
                                            </span>
                                            <span className="text-sm font-mono text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">
                                                {vuln.owasp}
                                            </span>
                                            <span className="text-sm text-gray-500 dark:text-gray-400">
                                                Confidence: {(vuln.confidence * 100).toFixed(0)}%
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                {/* Risk Overview / Explanation */}
                                {vuln.explanation && (
                                    <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-900/40 rounded-lg">
                                        <h4 className="font-semibold text-gray-900 dark:text-white mb-1 text-sm uppercase tracking-wide">
                                            🔎 Risk Overview
                                        </h4>
                                        <p className="text-gray-700 dark:text-gray-300 text-sm leading-relaxed">
                                            {renderMultiline(vuln.explanation)}
                                        </p>
                                    </div>
                                )}

                                {/* Technical Impact */}
                                {vuln.technical_impact && (
                                    <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-900/40 rounded-lg">
                                        <h4 className="font-semibold text-gray-900 dark:text-white mb-1 text-sm uppercase tracking-wide">
                                            📉 Technical Impact
                                        </h4>
                                        <p className="text-gray-700 dark:text-gray-300 text-sm leading-relaxed">
                                            {renderMultiline(vuln.technical_impact)}
                                        </p>
                                    </div>
                                )}

                                {/* Evidence */}
                                {vuln.evidence && (
                                    <div className="mb-4">
                                        <h4 className="font-semibold text-gray-900 dark:text-white mb-2 text-sm uppercase tracking-wide">
                                            🧾 Evidence
                                        </h4>
                                        <pre className="bg-gray-100 dark:bg-gray-900 p-4 rounded-lg text-xs overflow-x-auto text-gray-800 dark:text-gray-200 whitespace-pre-wrap break-words">
                                            {vuln.evidence}
                                        </pre>
                                    </div>
                                )}

                                {/* Mitigation */}
                                {vuln.mitigation && (
                                    <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                                        <h4 className="font-semibold text-green-900 dark:text-green-200 mb-2 text-sm uppercase tracking-wide">
                                            🛡️ Recommended Mitigation
                                        </h4>
                                        <div className="text-gray-800 dark:text-gray-200 text-sm leading-relaxed whitespace-pre-wrap">
                                            {renderMultiline(vuln.mitigation)}
                                        </div>
                                    </div>
                                )}

                                {/* Secure Implementation Example */}
                                {vuln.secure_example && (
                                    <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                                        <h4 className="font-semibold text-blue-900 dark:text-blue-200 mb-2 text-sm uppercase tracking-wide">
                                            💻 Secure Implementation Example
                                        </h4>
                                        <pre className="text-gray-800 dark:text-gray-200 text-xs leading-relaxed overflow-x-auto whitespace-pre-wrap">
                                            {vuln.secure_example}
                                        </pre>
                                    </div>
                                )}

                                {/* Severity Justification */}
                                {vuln.severity_justification && (
                                    <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 rounded-lg">
                                        <h4 className="font-semibold text-gray-700 dark:text-gray-300 mb-2 text-sm uppercase tracking-wide">
                                            ⚖️ Severity Justification
                                        </h4>
                                        <p className="text-gray-700 dark:text-gray-300 text-sm leading-relaxed">
                                            {renderMultiline(vuln.severity_justification)}
                                        </p>
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
