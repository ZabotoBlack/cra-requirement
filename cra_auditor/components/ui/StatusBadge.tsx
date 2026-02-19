import React from 'react';

interface StatusBadgeProps {
  label: string;
  tone?: 'success' | 'warning' | 'danger' | 'info' | 'neutral';
  pulse?: boolean;
}

const toneClasses: Record<NonNullable<StatusBadgeProps['tone']>, string> = {
  success: 'text-[var(--badge-success-text)] border-[var(--badge-success-border)] bg-[var(--badge-success-bg)]',
  warning: 'text-[var(--badge-warning-text)] border-[var(--badge-warning-border)] bg-[var(--badge-warning-bg)]',
  danger: 'text-[var(--badge-danger-text)] border-[var(--badge-danger-border)] bg-[var(--badge-danger-bg)]',
  info: 'text-[var(--badge-info-text)] border-[var(--badge-info-border)] bg-[var(--badge-info-bg)]',
  neutral: 'text-[var(--badge-neutral-text)] border-[var(--badge-neutral-border)] bg-[var(--badge-neutral-bg)]',
};

const StatusBadge: React.FC<StatusBadgeProps> = ({ label, tone = 'neutral', pulse = false }) => {
  return (
    <span className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${toneClasses[tone]}`}>
      <span className={`h-2 w-2 rounded-full ${pulse ? 'animate-pulse' : ''} ${tone === 'success' ? 'bg-emerald-400' : tone === 'warning' ? 'bg-amber-400' : tone === 'danger' ? 'bg-rose-400' : tone === 'info' ? 'bg-cyan-400' : 'bg-slate-400'}`} />
      {label}
    </span>
  );
};

export default StatusBadge;
