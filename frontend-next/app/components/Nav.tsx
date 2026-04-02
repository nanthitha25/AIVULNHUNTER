'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export default function Nav() {
    const [role, setRole] = useState<string | null>(null);
    const [isDemo, setIsDemo] = useState(false);
    const pathname = usePathname();

    useEffect(() => {
        // Check localStorage for role on mount and route changes
        const storedRole = localStorage.getItem('auth_role');
        const demoFlag = localStorage.getItem('is_demo') === 'true';
        setRole(storedRole);
        setIsDemo(demoFlag);
    }, [pathname]);

    const handleLogout = () => {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_role');
        localStorage.removeItem('is_demo');
        window.location.href = '/login';
    };

    return (
        <>
            {isDemo && (
                <div className="fixed top-0 left-0 right-0 z-50 bg-gradient-to-r from-orange-600 to-red-600 text-white text-xs font-bold text-center py-1 tracking-widest shadow-md">
                    DEMO MODE — LIMITED ACCESS (MAX 3 SCANS)
                </div>
            )}
            <nav className={`fixed ${isDemo ? 'top-6' : 'top-0'} left-0 right-0 z-40 bg-black/40 backdrop-blur-md border-b border-white/10 transition-all`}>
                <div className="max-w-7xl mx-auto px-6 flex items-center gap-6 h-12 justify-between">
                    <div className="flex items-center gap-6">
                        <Link href="/" className="text-sm font-bold text-white tracking-wide">
                            🛡️ AivulnHunter
                        </Link>
                        {role && (
                            <div className="flex gap-4 text-sm text-gray-400">
                                <Link href="/" className="hover:text-white transition-colors">Dashboard</Link>
                                <Link href="/scans" className="hover:text-white transition-colors">Scans</Link>
                                {role === 'admin' && (
                                    <>
                                        <Link href="/admin" className="hover:text-orange-400 transition-colors font-medium">Admin</Link>
                                        <Link href="/admin/rules" className="hover:text-orange-400 transition-colors font-medium">Rules</Link>
                                    </>
                                )}
                            </div>
                        )}
                    </div>
                    {role ? (
                        <button onClick={handleLogout} className="text-sm text-gray-400 hover:text-white transition-colors">
                            Logout ({role})
                        </button>
                    ) : (
                        <Link href="/login" className="text-sm text-blue-400 hover:text-blue-300">Login</Link>
                    )}
                </div>
            </nav>
        </>
    );
}
