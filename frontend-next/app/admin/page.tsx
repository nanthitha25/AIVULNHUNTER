'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// ─── Types ────────────────────────────────────────────────────────────────────

interface User {
    id: string;
    username: string;
    email: string;
    role: string;
    is_active: boolean;
    created_at: string | null;
    last_login: string | null;
}

interface Rule {
    id: number;
    name: string;
    owasp: string;
    severity: string;
    priority: number;
    description: string;
    enabled: boolean;
    target_types: string[];
    rl_weight: {
        weight: number;
        priority_score: number;
        success_count: number;
        failure_count: number;
        total_scans: number;
    } | null;
}

interface Stats {
    scans: { total: number; completed: number; failed: number; running: number };
    vulnerabilities: { total: number; by_severity: Record<string, number> };
    users: { total: number; active: number };
    rules: { total: number; enabled: number };
    top_rules_by_rl: {
        id: number; name: string; owasp: string;
        priority_score: number; success_count: number; total_scans: number;
    }[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function apiFetch(path: string, opts: RequestInit = {}) {
    const fullPath = path.startsWith('/api/v1') ? path : '/api/v1' + path;
    const token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null;
    const authHeaders: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

    const res = await fetch(`${API_BASE}${fullPath}`, {
        ...opts,
        headers: { 'Content-Type': 'application/json', ...authHeaders, ...opts.headers },
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

const SEVERITY_COLORS: Record<string, string> = {
    CRITICAL: 'text-purple-400',
    HIGH: 'text-red-400',
    MEDIUM: 'text-orange-400',
    LOW: 'text-yellow-400',
    INFO: 'text-blue-400',
};

const SEVERITY_BG: Record<string, string> = {
    CRITICAL: 'bg-purple-500',
    HIGH: 'bg-red-500',
    MEDIUM: 'bg-orange-500',
    LOW: 'bg-yellow-500',
    INFO: 'bg-blue-500',
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: { label: string; value: number; sub?: string; color: string }) {
    return (
        <div className={`rounded-xl p-5 border ${color} bg-white/5 backdrop-blur`}>
            <p className="text-xs text-gray-400 uppercase tracking-wider mb-1">{label}</p>
            <p className="text-3xl font-bold text-white">{value}</p>
            {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
        </div>
    );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AdminPage() {
    const [tab, setTab] = useState<'stats' | 'users' | 'rules'>('stats');
    const [stats, setStats] = useState<Stats | null>(null);
    const [users, setUsers] = useState<User[]>([]);
    const [rules, setRules] = useState<Rule[]>([]);
    const [loading, setLoading] = useState(false);
    const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

    // New-user form state
    const [newUser, setNewUser] = useState({ username: '', email: '', password: '', role: 'user' });
    const [showNewUser, setShowNewUser] = useState(false);

    const notify = (msg: string, ok = true) => {
        setToast({ msg, ok });
        setTimeout(() => setToast(null), 3000);
    };

    const router = useRouter();
    useEffect(() => {
        const role = localStorage.getItem('auth_role');
        if (role !== 'admin') {
            router.push('/');
        }
    }, [router]);

    // ── Data loaders ──────────────────────────────────────────────────────────

    const loadStats = async () => {
        setLoading(true);
        try { setStats(await apiFetch('/admin/stats')); }
        catch (e: any) { notify(e.message, false); }
        finally { setLoading(false); }
    };

    const loadUsers = async () => {
        setLoading(true);
        try { setUsers((await apiFetch('/admin/users')).users); }
        catch (e: any) { notify(e.message, false); }
        finally { setLoading(false); }
    };

    const loadRules = async () => {
        setLoading(true);
        try { setRules((await apiFetch('/admin/rules')).rules); }
        catch (e: any) { notify(e.message, false); }
        finally { setLoading(false); }
    };

    useEffect(() => {
        if (tab === 'stats') loadStats();
        else if (tab === 'users') loadUsers();
        else if (tab === 'rules') loadRules();
    }, [tab]);

    // ── User actions ──────────────────────────────────────────────────────────

    const createUser = async () => {
        try {
            await apiFetch('/admin/users', { method: 'POST', body: JSON.stringify(newUser) });
            notify('User created ✓');
            setShowNewUser(false);
            setNewUser({ username: '', email: '', password: '', role: 'user' });
            loadUsers();
        } catch (e: any) { notify(e.message, false); }
    };

    const toggleActive = async (u: User) => {
        try {
            if (!u.is_active) {
                await apiFetch(`/admin/users/${u.id}`, { method: 'PATCH', body: JSON.stringify({ is_active: true }) });
                notify(`${u.username} activated ✓`);
            } else {
                await apiFetch(`/admin/users/${u.id}`, { method: 'DELETE' });
                notify(`${u.username} deactivated ✓`);
            }
            loadUsers();
        } catch (e: any) { notify(e.message, false); }
    };

    const changeRole = async (u: User, role: string) => {
        try {
            await apiFetch(`/admin/users/${u.id}`, { method: 'PATCH', body: JSON.stringify({ role }) });
            notify(`Role updated ✓`);
            loadUsers();
        } catch (e: any) { notify(e.message, false); }
    };

    // ── Rule actions ──────────────────────────────────────────────────────────

    const toggleRule = async (r: Rule) => {
        try {
            await apiFetch(`/admin/rules/${r.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !r.enabled }) });
            notify(`Rule ${r.enabled ? 'disabled' : 'enabled'} ✓`);
            loadRules();
        } catch (e: any) { notify(e.message, false); }
    };

    const changePriority = async (r: Rule, priority: number) => {
        try {
            await apiFetch(`/admin/rules/${r.id}`, { method: 'PATCH', body: JSON.stringify({ priority }) });
            notify('Priority updated ✓');
            loadRules();
        } catch (e: any) { notify(e.message, false); }
    };

    const resetRL = async (r: Rule) => {
        try {
            await apiFetch(`/admin/rules/${r.id}/reset-rl`, { method: 'POST' });
            notify(`RL weights reset for ${r.name} ✓`);
            loadRules();
        } catch (e: any) { notify(e.message, false); }
    };

    // ─── Render ───────────────────────────────────────────────────────────────

    const tabs = [
        { key: 'stats', label: '📊 System Stats' },
        { key: 'users', label: '👥 Users' },
        { key: 'rules', label: '🛡️ Rules' },
    ] as const;

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-gray-900 to-slate-900 p-6">
            <div className="max-w-7xl mx-auto">

                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-400 to-orange-400">
                            Admin Panel
                        </h1>
                        <p className="text-gray-400 mt-1">Manage users, rules, and monitor system health</p>
                    </div>
                    <Link href="/" className="text-sm text-gray-400 hover:text-white transition-colors">
                        ← Dashboard
                    </Link>
                </div>

                {/* Toast */}
                {toast && (
                    <div className={`fixed top-4 right-4 z-50 px-5 py-3 rounded-lg shadow-lg text-white text-sm font-medium transition-all ${toast.ok ? 'bg-green-600' : 'bg-red-600'}`}>
                        {toast.msg}
                    </div>
                )}

                {/* Tabs */}
                <div className="flex gap-2 mb-6 border-b border-white/10 pb-0">
                    {tabs.map(t => (
                        <button
                            key={t.key}
                            onClick={() => setTab(t.key)}
                            className={`px-5 py-2.5 text-sm font-medium rounded-t-lg transition-all ${tab === t.key
                                ? 'bg-white/10 text-white border-b-2 border-orange-400'
                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                                }`}
                        >
                            {t.label}
                        </button>
                    ))}
                </div>

                {loading && (
                    <div className="flex justify-center py-16">
                        <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-orange-400" />
                    </div>
                )}

                {/* ── STATS TAB ─────────────────────────────────────────────────────── */}
                {tab === 'stats' && !loading && stats && (
                    <div className="space-y-6">
                        {/* KPI row */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <StatCard label="Total Scans" value={stats.scans.total} sub={`${stats.scans.completed} completed`} color="border-blue-500/30" />
                            <StatCard label="Running" value={stats.scans.running} color="border-green-500/30" />
                            <StatCard label="Failed" value={stats.scans.failed} color="border-red-500/30" />
                            <StatCard label="Vulnerabilities" value={stats.vulnerabilities.total} color="border-orange-500/30" />
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <StatCard label="Total Users" value={stats.users.total} sub={`${stats.users.active} active`} color="border-purple-500/30" />
                            <StatCard label="Total Rules" value={stats.rules.total} sub={`${stats.rules.enabled} enabled`} color="border-yellow-500/30" />
                        </div>

                        {/* Severity breakdown */}
                        <div className="bg-white/5 rounded-xl p-6 border border-white/10">
                            <h2 className="text-lg font-semibold text-white mb-4">Vulnerability Severity Breakdown</h2>
                            <div className="space-y-3">
                                {Object.entries(stats.vulnerabilities.by_severity).map(([sev, count]) => {
                                    const total = stats.vulnerabilities.total || 1;
                                    const pct = ((count / total) * 100).toFixed(1);
                                    return (
                                        <div key={sev}>
                                            <div className="flex justify-between text-sm mb-1">
                                                <span className={`font-medium ${SEVERITY_COLORS[sev] || 'text-gray-300'}`}>{sev}</span>
                                                <span className="text-gray-400">{count} ({pct}%)</span>
                                            </div>
                                            <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                                                <div className={`h-full ${SEVERITY_BG[sev] || 'bg-gray-500'}`} style={{ width: `${pct}%` }} />
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        {/* Top rules */}
                        <div className="bg-white/5 rounded-xl p-6 border border-white/10">
                            <h2 className="text-lg font-semibold text-white mb-4">Top Rules by RL Score</h2>
                            <table className="w-full text-sm">
                                <thead>
                                    <tr className="text-gray-400 text-left border-b border-white/10">
                                        <th className="pb-2">Rule</th>
                                        <th className="pb-2">OWASP</th>
                                        <th className="pb-2">RL Score</th>
                                        <th className="pb-2">Successes</th>
                                        <th className="pb-2">Total Runs</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5">
                                    {stats.top_rules_by_rl.map(r => (
                                        <tr key={r.id} className="text-gray-300">
                                            <td className="py-2 font-medium text-white">{r.name}</td>
                                            <td className="py-2 text-orange-400">{r.owasp}</td>
                                            <td className="py-2">{(r.priority_score * 100).toFixed(1)}%</td>
                                            <td className="py-2 text-green-400">{r.success_count}</td>
                                            <td className="py-2">{r.total_scans}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {/* ── USERS TAB ─────────────────────────────────────────────────────── */}
                {tab === 'users' && !loading && (
                    <div className="space-y-4">
                        <div className="flex justify-end">
                            <button
                                onClick={() => setShowNewUser(v => !v)}
                                className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg text-sm font-medium transition-colors"
                            >
                                {showNewUser ? 'Cancel' : '+ New User'}
                            </button>
                        </div>

                        {/* New user form */}
                        {showNewUser && (
                            <div className="bg-white/5 border border-white/10 rounded-xl p-6 space-y-4">
                                <h3 className="text-white font-semibold">Create User</h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {(['username', 'email', 'password'] as const).map(field => (
                                        <input
                                            key={field}
                                            type={field === 'password' ? 'password' : 'text'}
                                            placeholder={field.charAt(0).toUpperCase() + field.slice(1)}
                                            value={newUser[field]}
                                            onChange={e => setNewUser(v => ({ ...v, [field]: e.target.value }))}
                                            className="px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-orange-500"
                                        />
                                    ))}
                                    <select
                                        value={newUser.role}
                                        onChange={e => setNewUser(v => ({ ...v, role: e.target.value }))}
                                        className="px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
                                    >
                                        <option value="user">User</option>
                                        <option value="admin">Admin</option>
                                        <option value="viewer">Viewer</option>
                                    </select>
                                </div>
                                <button
                                    onClick={createUser}
                                    className="px-6 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium transition-colors"
                                >
                                    Create
                                </button>
                            </div>
                        )}

                        {/* Users table */}
                        <div className="bg-white/5 rounded-xl border border-white/10 overflow-hidden">
                            <table className="w-full text-sm">
                                <thead className="bg-white/5">
                                    <tr className="text-gray-400 text-left">
                                        <th className="px-6 py-3">Username</th>
                                        <th className="px-6 py-3">Email</th>
                                        <th className="px-6 py-3">Role</th>
                                        <th className="px-6 py-3">Status</th>
                                        <th className="px-6 py-3">Last Login</th>
                                        <th className="px-6 py-3">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5">
                                    {users.map(u => (
                                        <tr key={u.id} className="text-gray-300 hover:bg-white/5 transition-colors">
                                            <td className="px-6 py-4 font-medium text-white">{u.username}</td>
                                            <td className="px-6 py-4 text-gray-400">{u.email}</td>
                                            <td className="px-6 py-4">
                                                <select
                                                    value={u.role}
                                                    onChange={e => changeRole(u, e.target.value)}
                                                    className="bg-white/10 border border-white/20 rounded px-2 py-1 text-white text-xs focus:outline-none"
                                                >
                                                    <option value="admin">admin</option>
                                                    <option value="user">user</option>
                                                    <option value="viewer">viewer</option>
                                                </select>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${u.is_active ? 'bg-green-500/20 text-green-300' : 'bg-red-500/20 text-red-300'}`}>
                                                    {u.is_active ? 'Active' : 'Inactive'}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-gray-500 text-xs">
                                                {u.last_login ? new Date(u.last_login).toLocaleDateString() : 'Never'}
                                            </td>
                                            <td className="px-6 py-4">
                                                <button
                                                    onClick={() => toggleActive(u)}
                                                    disabled={u.username === 'admin'}
                                                    className={`px-3 py-1 rounded text-xs font-medium transition-colors ${u.username === 'admin'
                                                        ? 'opacity-30 cursor-not-allowed bg-gray-600 text-gray-400'
                                                        : u.is_active
                                                            ? 'bg-red-600/30 hover:bg-red-600/50 text-red-300'
                                                            : 'bg-green-600/30 hover:bg-green-600/50 text-green-300'
                                                        }`}
                                                >
                                                    {u.is_active ? 'Deactivate' : 'Activate'}
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {/* ── RULES TAB ─────────────────────────────────────────────────────── */}
                {tab === 'rules' && !loading && (
                    <div className="bg-white/5 rounded-xl border border-white/10 overflow-hidden">
                        <table className="w-full text-sm">
                            <thead className="bg-white/5">
                                <tr className="text-gray-400 text-left">
                                    <th className="px-6 py-3">Rule</th>
                                    <th className="px-6 py-3">OWASP</th>
                                    <th className="px-6 py-3">Severity</th>
                                    <th className="px-6 py-3">Priority</th>
                                    <th className="px-6 py-3">RL Score</th>
                                    <th className="px-6 py-3">Status</th>
                                    <th className="px-6 py-3">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/5">
                                {rules.map(r => (
                                    <tr key={r.id} className={`text-gray-300 hover:bg-white/5 transition-colors ${!r.enabled ? 'opacity-50' : ''}`}>
                                        <td className="px-6 py-4">
                                            <div className="font-medium text-white">{r.name}</div>
                                            <div className="text-xs text-gray-500 mt-0.5 max-w-xs truncate">{r.description}</div>
                                        </td>
                                        <td className="px-6 py-4 text-orange-400 font-mono text-xs">{r.owasp}</td>
                                        <td className="px-6 py-4">
                                            <span className={`font-semibold text-xs ${SEVERITY_COLORS[r.severity] || 'text-gray-300'}`}>
                                                {r.severity}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4">
                                            <input
                                                type="number"
                                                min={1}
                                                max={10}
                                                defaultValue={r.priority}
                                                onBlur={e => {
                                                    const val = parseInt(e.target.value);
                                                    if (val !== r.priority) changePriority(r, val);
                                                }}
                                                className="w-14 bg-white/10 border border-white/20 rounded px-2 py-1 text-white text-xs focus:outline-none focus:ring-1 focus:ring-orange-500"
                                            />
                                        </td>
                                        <td className="px-6 py-4">
                                            {r.rl_weight ? (
                                                <div>
                                                    <div className="text-xs font-medium text-white">
                                                        {(r.rl_weight.priority_score * 100).toFixed(1)}%
                                                    </div>
                                                    <div className="text-xs text-gray-500">
                                                        {r.rl_weight.success_count}✓ / {r.rl_weight.total_scans} runs
                                                    </div>
                                                </div>
                                            ) : '—'}
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${r.enabled ? 'bg-green-500/20 text-green-300' : 'bg-gray-500/20 text-gray-400'}`}>
                                                {r.enabled ? 'Enabled' : 'Disabled'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="flex gap-2">
                                                <button
                                                    onClick={() => toggleRule(r)}
                                                    className={`px-3 py-1 rounded text-xs font-medium transition-colors ${r.enabled
                                                        ? 'bg-red-600/30 hover:bg-red-600/50 text-red-300'
                                                        : 'bg-green-600/30 hover:bg-green-600/50 text-green-300'
                                                        }`}
                                                >
                                                    {r.enabled ? 'Disable' : 'Enable'}
                                                </button>
                                                <button
                                                    onClick={() => resetRL(r)}
                                                    className="px-3 py-1 rounded text-xs font-medium bg-yellow-600/30 hover:bg-yellow-600/50 text-yellow-300 transition-colors"
                                                >
                                                    Reset RL
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}
