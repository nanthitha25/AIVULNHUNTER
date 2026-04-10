'use client';

import { useState, useRef } from 'react';

interface ScanModalProps {
    isOpen: boolean;
    onClose: () => void;
    onStartScan: (data: { scan_context: string; file_type: string; file_name?: string }) => void;
}

export default function ScanModal({ isOpen, onClose, onStartScan }: ScanModalProps) {
    const [targetUrl, setTargetUrl] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);

    if (!isOpen) return null;

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        setIsLoading(true);
        const reader = new FileReader();
        reader.onload = (event) => {
            const content = event.target?.result as string;
            const fileType = file.name.endsWith('.json') ? 'json' : file.name.endsWith('.csv') ? 'csv' : 'url';
            
            onStartScan({
                scan_context: content,
                file_type: fileType,
                file_name: file.name
            });
            
            setIsLoading(false);
            onClose();
        };
        reader.onerror = () => {
            alert('Failed to read file');
            setIsLoading(false);
        };
        reader.readAsText(file);
    };

    const handleUrlSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!targetUrl.trim()) return;

        onStartScan({
            scan_context: targetUrl.trim(),
            file_type: 'url'
        });
        setTargetUrl('');
        onClose();
    };

    return (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
            <div className="bg-slate-900 border border-purple-500/30 rounded-2xl w-full max-w-md shadow-2xl shadow-purple-900/20 overflow-hidden transform animate-in slide-in-from-bottom-4 duration-300">
                {/* Header */}
                <div className="bg-gradient-to-r from-purple-900/50 to-indigo-900/50 p-6 border-b border-purple-500/20">
                    <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                        <span className="text-purple-400">🚀</span> Scan Target
                    </h2>
                    <p className="text-purple-200/60 text-sm mt-1">Configure your vulnerability audit</p>
                </div>

                <div className="p-6 space-y-6">
                    {/* URL Option */}
                    <form onSubmit={handleUrlSubmit} className="space-y-3">
                        <label className="text-sm font-semibold text-gray-300 block">Target URL (optional)</label>
                        <div className="flex gap-2">
                            <input
                                type="url"
                                value={targetUrl}
                                onChange={(e) => setTargetUrl(e.target.value)}
                                placeholder="https://api.example.com/v1"
                                className="flex-1 bg-slate-800/50 border border-slate-700 text-white rounded-xl px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-purple-500/50 placeholder-gray-500 transition-all text-sm"
                            />
                        </div>
                    </form>

                    {/* Divider */}
                    <div className="relative">
                        <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-800"></div></div>
                        <div className="relative flex justify-center text-xs uppercase"><span className="bg-slate-900 px-3 text-gray-500 font-bold tracking-widest">OR</span></div>
                    </div>

                    {/* File Upload Option */}
                    <div className="space-y-3">
                        <label className="text-sm font-semibold text-gray-300 block">Upload Scan File</label>
                        <input
                            type="file"
                            ref={fileInputRef}
                            onChange={handleFileChange}
                            accept=".json,.csv"
                            className="hidden"
                        />
                        <button
                            type="button"
                            onClick={() => fileInputRef.current?.click()}
                            disabled={isLoading}
                            className="w-full group bg-slate-800/50 hover:bg-slate-800 border-2 border-dashed border-slate-700 hover:border-purple-500/50 rounded-2xl p-8 transition-all flex flex-col items-center gap-3"
                        >
                            <div className="w-12 h-12 bg-purple-500/10 rounded-full flex items-center justify-center group-hover:scale-110 transition-transform">
                                <svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                            </div>
                            <div className="text-center">
                                <span className="text-white font-medium block">Click to upload</span>
                                <span className="text-gray-500 text-xs mt-1">Accepts JSON or CSV scan data</span>
                            </div>
                        </button>
                    </div>
                </div>

                {/* Footer */}
                <div className="p-6 bg-slate-950/50 flex gap-3 justify-end items-center">
                    <button
                        onClick={onClose}
                        className="px-5 py-2.5 text-sm font-medium text-gray-400 hover:text-white transition-colors"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleUrlSubmit}
                        disabled={!targetUrl.trim() || isLoading}
                        className="px-6 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-bold shadow-lg shadow-purple-900/20 transition-all text-sm"
                    >
                        {isLoading ? 'Processing...' : 'Start Audit'}
                    </button>
                </div>
            </div>
        </div>
    );
}
