import React, { useCallback, useEffect, useState } from 'react';
import { ArrowDown, ArrowUp, Calendar, Eye, Search, Target, Trash2 } from 'lucide-react';
import { deleteHistory, getHistory } from '../services/api';
import { useLanguage } from '../LanguageContext';
import { ScanHistoryItem } from '../types';
import GlassCard from './ui/GlassCard';
import StatusBadge from './ui/StatusBadge';
import TechButton from './ui/TechButton';

interface HistoryViewProps {
  onViewReport: (id: number) => void;
}

const SnapshotBar: React.FC<{ item: ScanHistoryItem }> = ({ item }) => {
  const { t } = useLanguage();
  const total = Math.max(item.summary.total, 1);
  const compliantPct = Math.round((item.summary.compliant / total) * 100);
  const warningPct = Math.round((item.summary.warning / total) * 100);
  const nonCompliantPct = Math.max(0, 100 - compliantPct - warningPct);

  return (
    <div>
      <div className="mb-2 h-2 overflow-hidden rounded-full bg-slate-800">
        <div className="flex h-full w-full">
          <div style={{ width: `${compliantPct}%` }} className="bg-emerald-400/90" />
          <div style={{ width: `${warningPct}%` }} className="bg-amber-400/90" />
          <div style={{ width: `${nonCompliantPct}%` }} className="bg-rose-400/90" />
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <StatusBadge label={`${item.summary.total} ${t('history.devices')}`} tone="info" />
        {item.summary.nonCompliant > 0 && <StatusBadge label={`${item.summary.nonCompliant} ${t('history.issues')}`} tone="danger" />}
        {item.summary.warning > 0 && <StatusBadge label={`${item.summary.warning} ${t('history.warnings')}`} tone="warning" />}
      </div>
    </div>
  );
};

const HistoryView: React.FC<HistoryViewProps> = ({ onViewReport }) => {
  const { t } = useLanguage();
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'timestamp' | 'target'>('timestamp');
  const [order, setOrder] = useState<'asc' | 'desc'>('desc');

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    const data = await getHistory(search, sortBy, order);
    setHistory(data);
    setLoading(false);
  }, [search, sortBy, order]);

  useEffect(() => {
    const debounce = setTimeout(fetchHistory, 300);
    return () => clearTimeout(debounce);
  }, [fetchHistory, search, sortBy, order]);

  const handleDelete = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm(t('history.confirmDelete'))) {
      const success = await deleteHistory(id);
      if (success) fetchHistory();
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

  const sortIcon = (field: 'timestamp' | 'target') => {
    if (sortBy !== field) return null;
    return order === 'asc' ? <ArrowUp size={14} /> : <ArrowDown size={14} />;
  };

  return (
    <div className="space-y-4">
      <GlassCard className="rounded-2xl p-5">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-lg font-bold text-white">{t('history.title')}</h2>
            <p className="text-sm text-slate-300">{t('history.subtitle')}</p>
          </div>

          <div className="relative w-full md:w-auto">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={15} />
            <input
              type="text"
              placeholder={t('history.searchPlaceholder')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-900/85 py-2 pl-9 pr-3 text-sm text-slate-100 outline-none placeholder:text-slate-500 md:w-72"
            />
          </div>
        </div>

        <div className="mt-3 flex gap-2">
          <button
            onClick={() => toggleSort('timestamp')}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-sm font-semibold uppercase tracking-wider text-slate-300 hover:text-white"
          >
            <Calendar size={13} /> {t('history.date')} {sortIcon('timestamp')}
          </button>
          <button
            onClick={() => toggleSort('target')}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 text-sm font-semibold uppercase tracking-wider text-slate-300 hover:text-white"
          >
            <Target size={13} /> {t('history.target')} {sortIcon('target')}
          </button>
        </div>
      </GlassCard>

      <GlassCard className="rounded-2xl p-5">
        {loading ? (
          <div className="py-20 text-center text-sm text-slate-500">{t('history.loading')}</div>
        ) : history.length === 0 ? (
          <div className="py-20 text-center text-sm text-slate-500">{t('history.none')}</div>
        ) : (
          <div className="space-y-4">
            {history.map((item, index) => (
              <div key={item.id} className="relative rounded-xl border border-slate-700/70 bg-slate-900/50 p-5">
                <div className="absolute -left-[26px] top-6 hidden h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.8)] lg:block" />
                {index < history.length - 1 && <div className="absolute -left-[23px] top-8 hidden h-[calc(100%+12px)] w-px bg-slate-700 lg:block" />}

                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-100">{new Date(item.timestamp).toLocaleString()}</p>
                    <p className="font-mono text-sm text-cyan-200">{item.target_range}</p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <TechButton variant="secondary" className="px-3 py-1.5 text-xs" onClick={() => onViewReport(item.id)}>
                      <Eye size={14} /> {t('history.view')}
                    </TechButton>
                    <TechButton variant="danger" className="px-3 py-1.5 text-xs" onClick={(e) => handleDelete(item.id, e)}>
                      <Trash2 size={14} /> {t('history.delete')}
                    </TechButton>
                  </div>
                </div>

                <div className="mt-3">
                  <SnapshotBar item={item} />
                </div>
              </div>
            ))}
          </div>
        )}
      </GlassCard>
    </div>
  );
};

export default HistoryView;
