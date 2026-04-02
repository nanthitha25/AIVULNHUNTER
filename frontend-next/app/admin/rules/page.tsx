'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { APIClient, Rule } from '@/lib/api';

export default function AdminRulesPage() {
    const [rules, setRules] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const router = useRouter();

    const [newRule, setNewRule] = useState({
        name: '',
        owasp: '',
        severity: 'MEDIUM',
        target_types: 'WEB_APP',
        description: '',
        enabled: true,
    });

    useEffect(() => {
        const role = localStorage.getItem('auth_role');
        if (role !== 'admin') {
            router.push('/');
        } else {
            fetchRules();
        }
    }, [router]);

    const fetchRules = async () => {
        try {
            const api = new APIClient();
            const res = await fetch(`${api['baseURL']}/api/v1/rules/`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                }
            });
            if (!res.ok) throw new Error('Failed to fetch rules');
            const data = await res.json();
            setRules(data);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleToggleRule = async (ruleId: number, currentStatus: boolean) => {
        try {
            const api = new APIClient();
            const res = await fetch(`${api['baseURL']}/api/v1/rules/${ruleId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                },
                body: JSON.stringify({ enabled: !currentStatus })
            });
            if (!res.ok) throw new Error('Failed to toggle rule');
            fetchRules(); // Refresh
        } catch (err: any) {
            setError(err.message);
        }
    };

    const handleDeleteRule = async (ruleId: number) => {
        if (!window.confirm("Are you sure you want to delete this rule?")) return;
        try {
            const api = new APIClient();
            const res = await fetch(`${api['baseURL']}/api/v1/rules/${ruleId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                }
            });
            if (!res.ok) throw new Error('Failed to delete rule');
            fetchRules(); // Refresh
        } catch (err: any) {
            setError(err.message);
        }
    };

    const handleCreateRule = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setSuccess('');
        try {
            const api = new APIClient();
            const payload = {
                ...newRule,
                target_types: [newRule.target_types]
            };
            const res = await fetch(`${api['baseURL']}/api/v1/rules/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
                },
                body: JSON.stringify(payload)
            });

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || 'Failed to create rule');
            }

            setSuccess('Rule created successfully! RL weights initialized.');
            setNewRule({ name: '', owasp: '', severity: 'MEDIUM', target_types: 'WEB_APP', description: '', enabled: true });
            fetchRules(); // Refresh list
        } catch (err: any) {
            setError(err.message);
        }
    };

    if (loading) {
        return <div className="p-8 mt-12 text-white">Loading rules...</div>;
    }

    return (
        <div className="max-w-7xl mx-auto p-8 mt-16 text-white space-y-8">
            <h1 className="text-3xl font-bold mb-8">Admin Rule Management</h1>

            {error && <div className="bg-red-500/20 text-red-300 px-4 py-3 rounded-md">{error}</div>}
            {success && <div className="bg-green-500/20 text-green-300 px-4 py-3 rounded-md">{success}</div>}

            {/* Create Rule Form */}
            <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 shadow-xl">
                <h2 className="text-xl font-semibold mb-4 text-orange-400">Add New Rule</h2>
                <form onSubmit={handleCreateRule} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium mb-1">Rule Name</label>
                        <input type="text" required value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} className="w-full bg-slate-900 border border-slate-700 rounded p-2 focus:ring-orange-500" placeholder="e.g. SQL Injection Detection" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1">OWASP ID</label>
                        <input type="text" required value={newRule.owasp} onChange={(e) => setNewRule({ ...newRule, owasp: e.target.value })} className="w-full bg-slate-900 border border-slate-700 rounded p-2 focus:ring-orange-500" placeholder="e.g. A03:2021" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1">Severity</label>
                        <select value={newRule.severity} onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })} className="w-full bg-slate-900 border border-slate-700 rounded p-2">
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MEDIUM">MEDIUM</option>
                            <option value="LOW">LOW</option>
                            <option value="INFO">INFO</option>
                        </select>
                    </div>
                    <div>
                        <label className="block text-sm font-medium mb-1">Target Type</label>
                        <select value={newRule.target_types} onChange={(e) => setNewRule({ ...newRule, target_types: e.target.value })} className="w-full bg-slate-900 border border-slate-700 rounded p-2">
                            <option value="WEB_APP">WEB_APP</option>
                            <option value="API">API</option>
                            <option value="LLM">LLM</option>
                            <option value="AGENT">AGENT</option>
                        </select>
                    </div>
                    <div className="md:col-span-2">
                        <label className="block text-sm font-medium mb-1">Description</label>
                        <textarea required value={newRule.description} onChange={(e) => setNewRule({ ...newRule, description: e.target.value })} className="w-full bg-slate-900 border border-slate-700 rounded p-2" rows={3}></textarea>
                    </div>
                    <div className="md:col-span-2 flex items-center gap-2">
                        <input type="checkbox" checked={newRule.enabled} onChange={(e) => setNewRule({ ...newRule, enabled: e.target.checked })} className="w-4 h-4 text-orange-500" />
                        <label className="text-sm">Enabled by default</label>
                    </div>
                    <div className="md:col-span-2">
                        <button type="submit" className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded font-medium shadow transition-colors">
                            Create Rule & Init RL Weight
                        </button>
                    </div>
                </form>
            </div>

            {/* Rules List */}
            <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
                <h2 className="text-xl font-semibold mb-4">Pipeline Rules ({rules.length})</h2>
                <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm text-gray-300">
                        <thead className="bg-slate-900 text-gray-400 capitalize">
                            <tr>
                                <th className="px-4 py-3">ID</th>
                                <th className="px-4 py-3">Name</th>
                                <th className="px-4 py-3">OWASP</th>
                                <th className="px-4 py-3">Severity</th>
                                <th className="px-4 py-3">RL Priority</th>
                                <th className="px-4 py-3">Status</th>
                                <th className="px-4 py-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rules.map((rule) => (
                                <tr key={rule.id} className="border-b border-slate-700 hover:bg-slate-700/50">
                                    <td className="px-4 py-3 font-mono">{rule.id}</td>
                                    <td className="px-4 py-3 font-medium text-white">{rule.name}</td>
                                    <td className="px-4 py-3 text-orange-400">{rule.owasp}</td>
                                    <td className="px-4 py-3">
                                        <span className={`px-2 py-1 rounded text-xs font-bold ${rule.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500' :
                                                rule.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-500' :
                                                    'bg-yellow-500/20 text-yellow-500'
                                            }`}>
                                            {rule.severity}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 font-mono text-blue-400">
                                        {rule.priority_score !== null ? rule.priority_score.toFixed(3) : 'N/A'}
                                    </td>
                                    <td className="px-4 py-3 flex gap-2">
                                        <button
                                            onClick={() => handleToggleRule(rule.id, rule.enabled)}
                                            className={`px-3 py-1 text-xs rounded-full font-bold transition-colors ${rule.enabled ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' : 'bg-gray-500/20 text-gray-400 hover:bg-gray-500/30'}`}
                                        >
                                            {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                                        </button>
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                        <button
                                            onClick={() => handleDeleteRule(rule.id)}
                                            className="text-red-400 hover:text-red-300 font-medium text-sm transition-colors"
                                        >
                                            Delete
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
}
