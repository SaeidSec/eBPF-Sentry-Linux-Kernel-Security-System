import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Activity, Lock, Terminal } from 'lucide-react';

const API_BASE = 'http://localhost:5000/api';

function App() {
    const [stats, setStats] = useState({ total_events: 0, high: 0, medium: 0, low: 0 });
    const [events, setEvents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedLog, setSelectedLog] = useState(null);

    const fetchData = async () => {
        try {
            const statsRes = await axios.get(`${API_BASE}/stats`);
            const eventsRes = await axios.get(`${API_BASE}/events?limit=20`);
            setStats(statsRes.data);
            setEvents(eventsRes.data);
            setLoading(false);
        } catch (error) {
            console.error("Error fetching data:", error);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 2000); // Poll every 2s
        return () => clearInterval(interval);
    }, []);

    const dataPie = [
        { name: 'High', value: stats.high, color: '#f7768e' },
        { name: 'Medium', value: stats.medium, color: '#e0af68' },
        { name: 'Low', value: stats.low, color: '#7aa2f7' },
    ];

    return (
        <div className="min-h-screen bg-dark-900 p-6 relative">
            {/* Detail Modal */}
            {selectedLog && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={() => setSelectedLog(null)}>
                    <div className="bg-dark-800 rounded-xl border border-dark-700 w-full max-w-2xl max-h-[80vh] overflow-y-auto shadow-2xl" onClick={e => e.stopPropagation()}>
                        <div className="p-6 border-b border-dark-700 flex justify-between items-center sticky top-0 bg-dark-800">
                            <h3 className="text-xl font-bold text-gray-100 flex items-center gap-3">
                                <SeverityBadge level={selectedLog.severity} />
                                Event Details
                            </h3>
                            <button
                                onClick={() => setSelectedLog(null)}
                                className="text-gray-400 hover:text-white transition-colors"
                            >
                                ✕
                            </button>
                        </div>
                        <div className="p-6 space-y-4">
                            <DetailRow label="Timestamp" value={new Date(selectedLog.timestamp).toLocaleString()} />
                            <DetailRow label="Rule Name" value={selectedLog.rule_name} highlight />
                            <DetailRow label="Process" value={selectedLog.process} mono />
                            <DetailRow label="Log Type" value={selectedLog.log_type?.toUpperCase()} />

                            <div className="pt-4 border-t border-dark-700">
                                <h4 className="text-sm font-semibold text-gray-400 mb-2">Message Payload</h4>
                                <div className="bg-dark-900 p-4 rounded-lg font-mono text-xs text-gray-300 whitespace-pre-wrap break-all overflow-x-auto">
                                    {/* Try to parse raw_data if it's a string looking like JSON, else just show it */}
                                    {(() => {
                                        try {
                                            // Attempt to clean and parse JSON if it was stringified weirdly
                                            return JSON.stringify(JSON.parse(selectedLog.raw_data.replace(/'/g, '"')), null, 2);
                                        } catch {
                                            // Fallback for objects or plain strings
                                            try {
                                                return JSON.stringify(eval("(" + selectedLog.raw_data + ")"), null, 2).replace(/\\'/g, "'");
                                            } catch {
                                                return selectedLog.raw_data || selectedLog.details;
                                            }
                                        }
                                    })()}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Header */}
            <header className="flex justify-between items-center mb-8">
                <div className="flex items-center gap-3">
                    <Shield className="w-8 h-8 text-primary" />
                    <h1 className="text-2xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
                        eBPF-Sentry Dashboard
                    </h1>
                </div>
                <div className="flex gap-4">
                    <div className="bg-dark-800 px-4 py-2 rounded-lg flex items-center gap-2 border border-dark-700">
                        <span className="w-2 h-2 rounded-full bg-success animate-pulse"></span>
                        <span className="text-sm text-gray-400">System Active</span>
                    </div>
                </div>
            </header>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <StatCard icon={<Activity />} title="Total Events" value={stats.total_events} color="text-primary" />
                <StatCard icon={<AlertTriangle />} title="High Severity" value={stats.high} color="text-danger" />
                <StatCard icon={<Lock />} title="Medium Severity" value={stats.medium} color="text-warning" />
                <StatCard icon={<Terminal />} title="Low Severity" value={stats.low} color="text-success" />
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                {/* Severity Distribution */}
                <div className="bg-dark-800 p-6 rounded-xl border border-dark-700 col-span-1">
                    <h3 className="text-lg font-semibold mb-4 text-gray-200">Severity Distribution</h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={dataPie}
                                    innerRadius={60}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {dataPie.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#24283b', borderColor: '#414868' }}
                                    itemStyle={{ color: '#fff' }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Live Event Feed Placeholder (Chart) */}
                <div className="bg-dark-800 p-6 rounded-xl border border-dark-700 col-span-2">
                    <h3 className="text-lg font-semibold mb-4 text-gray-200">Live Traffic (Mock Trend)</h3>
                    <div className="h-64 flex items-center justify-center text-gray-500">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={events.slice(0, 10).map((e, i) => ({ name: i, uv: Math.random() * 100 }))}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#414868" />
                                <XAxis dataKey="name" stroke="#565f89" />
                                <YAxis stroke="#565f89" />
                                <Tooltip contentStyle={{ backgroundColor: '#24283b', borderColor: '#414868' }} />
                                <Line type="monotone" dataKey="uv" stroke="#bb9af7" strokeWidth={2} dot={false} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* Recent Alerts Table */}
            <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
                <div className="p-6 border-b border-dark-700">
                    <h3 className="text-lg font-semibold text-gray-200">Recent Alerts (Click for Details)</h3>
                </div>
                <div className="overflow-x-auto">
                    <table className="w-full text-left">
                        <thead className="bg-dark-900 text-gray-400">
                            <tr>
                                <th className="p-4">Time</th>
                                <th className="p-4">Severity</th>
                                <th className="p-4">Rule</th>
                                <th className="p-4">Process</th>
                                <th className="p-4">Details</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-dark-700 text-gray-300">
                            {events.map((event) => (
                                <tr
                                    key={event.id}
                                    onClick={() => setSelectedLog(event)}
                                    className="hover:bg-dark-700/50 transition-colors cursor-pointer group"
                                >
                                    <td className="p-4 text-sm font-mono text-gray-500 group-hover:text-gray-300 transition-colors">
                                        {new Date(event.timestamp).toLocaleTimeString()}
                                    </td>
                                    <td className="p-4">
                                        <SeverityBadge level={event.severity} />
                                    </td>
                                    <td className="p-4 font-medium text-primary">{event.rule_name}</td>
                                    <td className="p-4 font-mono text-xs">
                                        <span className="bg-dark-900/50 rounded px-2 py-1">
                                            {event.process}
                                        </span>
                                    </td>
                                    <td className="p-4 text-gray-400 text-sm truncate max-w-md">
                                        {event.details}
                                    </td>
                                </tr>
                            ))}
                            {events.length === 0 && (
                                <tr>
                                    <td colSpan="5" className="p-8 text-center text-gray-500">
                                        No events detected yet...
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

function DetailRow({ label, value, mono = false, highlight = false }) {
    return (
        <div className="flex flex-col sm:flex-row sm:items-baseline gap-1 sm:gap-4">
            <span className="text-sm font-medium text-gray-500 w-24 shrink-0">{label}</span>
            <span className={`text-sm break-all ${mono ? 'font-mono bg-dark-900 px-2 py-0.5 rounded' : ''} ${highlight ? 'text-primary font-semibold' : 'text-gray-200'}`}>
                {value || 'N/A'}
            </span>
        </div>
    );
}

function StatCard({ icon, title, value, color }) {
    return (
        <div className="bg-dark-800 p-6 rounded-xl border border-dark-700 hover:border-dark-700/80 transition-all">
            <div className="flex justify-between items-start mb-4">
                <div className={`p-3 rounded-lg bg-dark-900 ${color} bg-opacity-10`}>
                    {React.cloneElement(icon, { size: 24, className: color })}
                </div>
            </div>
            <h4 className="text-gray-400 text-sm font-medium mb-1">{title}</h4>
            <span className="text-2xl font-bold text-gray-100">{value}</span>
        </div>
    );
}

function SeverityBadge({ level }) {
    const styles = {
        high: "bg-danger/10 text-danger border-danger/20",
        medium: "bg-warning/10 text-warning border-warning/20",
        low: "bg-success/10 text-success border-success/20",
        info: "bg-primary/10 text-primary border-primary/20"
    };

    const defaultStyle = styles.info;
    const activeStyle = styles[level?.toLowerCase()] || defaultStyle;

    return (
        <span className={`px-2 py-1 rounded-md text-xs font-medium border ${activeStyle}`}>
            {level?.toUpperCase() || 'INFO'}
        </span>
    );
}

export default App;
