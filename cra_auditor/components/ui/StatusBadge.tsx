import React from 'react';

interface StatusBadgeProps {
  label: string;
  tone?: 'success' | 'warning' | 'danger' | 'info' | 'neutral';
  pulse?: boolean;
}

const toneClasses: Record<NonNullable<StatusBadgeProps['tone']>, string> = {
  success: 'text-emerald-300 border-emerald-400/30 bg-emerald-500/10',
  warning: 'text-amber-300 border-amber-400/30 bg-amber-500/10',
  danger: 'text-rose-300 border-rose-400/30 bg-rose-500/10',
  info: 'text-cyan-300 border-cyan-400/30 bg-cyan-500/10',
  neutral: 'text-slate-300 border-slate-500/30 bg-slate-500/10',
};

const StatusBadge: React.FC<StatusBadgeProps> = ({ label, tone = 'neutral', pulse = false }) => {
  return (
    <span className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider ${toneClasses[tone]}`}>
      <span className={`h-2 w-2 rounded-full ${pulse ? 'animate-pulse' : ''} ${tone === 'success' ? 'bg-emerald-400' : tone === 'warning' ? 'bg-amber-400' : tone === 'danger' ? 'bg-rose-400' : tone === 'info' ? 'bg-cyan-400' : 'bg-slate-400'}`} />
      {label}
    </span>
  );
};

export default StatusBadge;
