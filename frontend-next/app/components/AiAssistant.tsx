'use client';

import { useState, useRef, useEffect } from 'react';

interface Message {
    role: 'user' | 'assistant';
    content: string;
}

export default function AiAssistant() {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState<Message[]>([
        { role: 'assistant', content: 'Hi! I am the AIVulnHunter Security Assistant. How can I help you understand your scans or AI vulnerabilities?' }
    ]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    useEffect(() => {
        if (isOpen) {
            scrollToBottom();
        }
    }, [messages, isOpen]);

    const sendMessage = async (e?: React.FormEvent) => {
        e?.preventDefault();
        if (!input.trim() || isLoading) return;

        const userMsg = input.trim();
        setInput('');
        setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
        setIsLoading(true);

        try {
            const res = await fetch('http://localhost:8000/api/v1/assistant/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: userMsg })
            });

            if (!res.ok) throw new Error('Network response was not ok');
            const data = await res.json();
            
            setMessages(prev => [...prev, { role: 'assistant', content: data.response || data.explanation || 'Sorry, I could not process that.' }]);
        } catch (error) {
            console.error('Error fetching assistant response:', error);
            setMessages(prev => [...prev, { role: 'assistant', content: '⚠️ Error: Could not connect to the AI Assistant service.' }]);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="fixed bottom-6 right-6 z-50">
            {/* Chat Window */}
            {isOpen && (
                <div className="mb-4 w-80 sm:w-96 h-[500px] max-h-[80vh] bg-[#0a0514] border border-purple-500/30 rounded-2xl shadow-2xl shadow-purple-900/50 flex flex-col overflow-hidden animate-in slide-in-from-bottom-5">
                    {/* Header */}
                    <div className="bg-gradient-to-r from-purple-900 to-indigo-900 p-4 flex justify-between items-center border-b border-purple-500/20">
                        <div className="flex items-center gap-2">
                            <span className="text-xl">🤖</span>
                            <h3 className="text-white font-bold text-sm tracking-wide">AI Security Assistant</h3>
                        </div>
                        <button 
                            onClick={() => setIsOpen(false)}
                            className="text-gray-400 hover:text-white transition-colors"
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                        </button>
                    </div>

                    {/* Messages Area */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-purple-900 scrollbar-track-transparent">
                        {messages.map((msg, idx) => (
                            <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                <div className={`max-w-[85%] rounded-xl p-3 text-sm shadow-md ${msg.role === 'user' ? 'bg-purple-600 text-white rounded-tr-none shadow-purple-900/40' : 'bg-gray-800/80 text-gray-200 border border-gray-700 rounded-tl-none shadow-black/40'}`}>
                                    <div className="whitespace-pre-wrap font-sans leading-relaxed">{msg.content}</div>
                                </div>
                            </div>
                        ))}
                        {isLoading && (
                            <div className="flex justify-start">
                                <div className="bg-gray-800/80 text-gray-400 border border-gray-700 rounded-xl rounded-tl-none p-4 text-sm flex gap-1 items-center shadow-md shadow-black/40">
                                    <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce"></div>
                                    <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                                    <div className="w-2 h-2 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }}></div>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input Area */}
                    <div className="p-3 border-t border-purple-500/20 bg-gray-900/80 backdrop-blur-sm">
                        <form onSubmit={sendMessage} className="flex gap-2">
                            <input
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                placeholder="Ask about vulnerabilities..."
                                className="flex-1 bg-gray-800/50 text-white text-sm rounded-xl px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-purple-500/50 border border-gray-700/50 placeholder-gray-500 transition-all"
                            />
                            <button
                                type="submit"
                                disabled={isLoading || !input.trim()}
                                className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50 disabled:from-gray-700 disabled:to-gray-700 disabled:cursor-not-allowed text-white rounded-xl px-4 py-2 transition-all focus:outline-none focus:ring-2 focus:ring-purple-500/50 shadow-lg shadow-purple-900/20"
                            >
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path></svg>
                            </button>
                        </form>
                    </div>
                </div>
            )}

            {/* Toggle Button */}
            {!isOpen && (
                <button
                    onClick={() => setIsOpen(true)}
                    className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-full px-5 py-4 shadow-xl shadow-purple-900/50 transition-all hover:scale-105 hover:-translate-y-1 flex items-center justify-center group border border-purple-500/30"
                >
                    <span className="text-2xl mr-2 group-hover:animate-pulse">🤖</span>
                    <span className="font-bold text-sm tracking-wide">Ask AI</span>
                </button>
            )}
        </div>
    );
}
