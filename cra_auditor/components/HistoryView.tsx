import React, { useEffect, useState } from 'react';
import { Clock, Search, Trash2, Eye, Calendar, Target, ShieldAlert, ArrowUp, ArrowDown } from 'lucide-react';
import { getHistory, deleteHistory } from '../services/api';
import { ScanHistoryItem } from '../types';

interface HistoryViewProps {
    onViewReport: (id: number) => void;
}

const HistoryView: React.FC<HistoryViewProps> = ({ onViewReport }) => {
    const [history, setHistory] = useState<ScanHistoryItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState('');
    const [sortBy, setSortBy] = useState<'timestamp' | 'target'>('timestamp');
    const [order, setOrder] = useState<'asc' | 'desc'>('desc');

    const fetchHistory = async () => {
        setLoading(true);
        const data = await getHistory(search, sortBy, order);
        setHistory(data);
        setLoading(false);
    };

    useEffect(() => {
        const debounce = setTimeout(fetchHistory, 300);
        return () => clearTimeout(debounce);
    }, [search, sortBy, order]);

    const handleDelete = async (id: number, e: React.MouseEvent) => {
        e.stopPropagation();
        if (confirm('Are you sure you want to delete this scan report?')) {
            const success = await deleteHistory(id);
            if (success) {
                fetchHistory();
            }
        }
    };

    const toggleSort = (field: 'timestamp' | 'target') => {
        if (sortBy === field) {
            setOrder(order === 'asc' ? 'desc' : 'asc');
        } else {
            setSortBy(field);
            setOrder('desc');
        }
    };

    const SortIcon = ({ field }: { field: 'timestamp' | 'target' }) => {
        if (sortBy !== field) return null;
        return order === 'asc' ? <ArrowUp size={14} /> : <ArrowDown size={14} />;
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between gap-4">
                <h2 className="text-2xl font-bold text-white">Scan History</h2>

                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                    <input
                        type="text"
                        placeholder="Search targets..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none focus:border-indigo-500 w-64"
                    />
                </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
                <div className="grid grid-cols-12 gap-4 px-6 py-3 bg-slate-800/50 border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    <div
                        className="col-span-3 flex items-center gap-2 cursor-pointer hover:text-white transition-colors"
                        onClick={() => toggleSort('timestamp')}
                    >
                        <Calendar size={14} /> Date <SortIcon field="timestamp" />
                    </div>
                    <div
                        className="col-span-3 flex items-center gap-2 cursor-pointer hover:text-white transition-colors"
                        onClick={() => toggleSort('target')}
                    >
                        <Target size={14} /> Target <SortIcon field="target" />
                    </div>
                    <div className="col-span-4 flex items-center gap-2">
                        <ShieldAlert size={14} /> Summary
                    </div>
                    <div className="col-span-2 text-right">Actions</div>
                </div>

                {loading ? (
                    <div className="p-8 text-center text-slate-500">Loading history...</div>
                ) : history.length === 0 ? (
                    <div className="p-8 text-center text-slate-500">No history found.</div>
                ) : (
                    <div className="divide-y divide-slate-800">
                        {history.map((item) => (
                            <div
                                key={item.id}
                                className="grid grid-cols-12 gap-4 px-6 py-4 items-center hover:bg-slate-800/30 transition-colors group"
                            >
                                <div className="col-span-3 text-slate-300 font-medium">
                                    {new Date(item.timestamp).toLocaleString()}
                                </div>
                                <div className="col-span-3 text-emerald-400 font-mono text-sm">
                                    {item.target_range}
                                </div>
                                <div className="col-span-4 flex gap-3 text-xs">
                                    <span className="px-2 py-1 rounded bg-slate-800 text-slate-400 border border-slate-700">
                                        {item.summary.total} Devices
                                    </span>
                                    {item.summary.nonCompliant > 0 && (
                                        <span className="px-2 py-1 rounded bg-red-900/20 text-red-400 border border-red-900/30">
                                            {item.summary.nonCompliant} Issues
                                        </span>
                                    )}
                                    {item.summary.warning > 0 && (
                                        <span className="px-2 py-1 rounded bg-amber-900/20 text-amber-400 border border-amber-900/30">
                                            {item.summary.warning} Warnings
                                        </span>
                                    )}
                                </div>
                                <div className="col-span-2 flex justify-end gap-2 opacity-60 group-hover:opacity-100 transition-opacity">
                                    <button
                                        onClick={() => onViewReport(item.id)}
                                        className="p-2 rounded-lg bg-indigo-600/10 text-indigo-400 hover:bg-indigo-600 hover:text-white transition-colors"
                                        title="View Report"
                                    >
                                        <Eye size={16} />
                                    </button>
                                    <button
                                        onClick={(e) => handleDelete(item.id, e)}
                                        className="p-2 rounded-lg bg-red-600/10 text-red-400 hover:bg-red-600 hover:text-white transition-colors"
                                        title="Delete Report"
                                    >
                                        <Trash2 size={16} />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default HistoryView;
