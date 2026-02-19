import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Link from "next/link";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AivulnHunter",
  description: "AI-powered vulnerability scanner for LLM APIs",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
        {/* Global Nav */}
        <nav className="fixed top-0 left-0 right-0 z-40 bg-black/40 backdrop-blur-md border-b border-white/10">
          <div className="max-w-7xl mx-auto px-6 flex items-center gap-6 h-12">
            <Link href="/" className="text-sm font-bold text-white tracking-wide">
              🛡️ AivulnHunter
            </Link>
            <div className="flex gap-4 text-sm text-gray-400">
              <Link href="/" className="hover:text-white transition-colors">Dashboard</Link>
              <Link href="/scans" className="hover:text-white transition-colors">Scans</Link>
              <Link href="/admin" className="hover:text-orange-400 transition-colors font-medium">Admin</Link>
            </div>
          </div>
        </nav>
        {/* Push content below nav */}
        <div className="pt-12">
          {children}
        </div>
      </body>
    </html>
  );
}
