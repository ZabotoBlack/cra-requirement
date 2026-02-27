import React, { useMemo } from 'react';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { useLanguage } from '../../LanguageContext';
import { ScanReport } from '../../types';
import GlassCard from '../ui/GlassCard';
import StatusBadge from '../ui/StatusBadge';

interface BasicDashboardProps {
  report: ScanReport;
}

const BasicDashboard: React.FC<BasicDashboardProps> = ({ report }) => {
  const { t } = useLanguage();
  const hasAttentionRequired = report.summary.nonCompliant > 0 || report.summary.warning > 0;

  const issueSummary = useMemo(() => {
    const defaultPasswordCount = report.devices.filter((device) => {
      const details = (device.checks?.secureByDefault?.details || '').toLowerCase();
      return details.includes('default credential') || details.includes('default password');
    }).length;

    const updateCount = report.devices.filter((device) => {
      return device.checks?.firmwareTracking?.update_available === true;
    }).length;

    const vulnerabilityCount = report.devices.filter((device) => {
      const cves = device.checks?.vulnerabilities?.cves || [];
      return cves.length > 0;
    }).length;

    const summary: string[] = [];
    if (defaultPasswordCount > 0) {
      summary.push(`${defaultPasswordCount} ${t('basic.issue.devices')} ${t('basic.issue.defaultPasswords')}`);
    }
    if (updateCount > 0) {
      summary.push(`${updateCount} ${t('basic.issue.devices')} ${t('basic.issue.firmwareUpdates')}`);
    }
    if (vulnerabilityCount > 0) {
      summary.push(`${vulnerabilityCount} ${t('basic.issue.devices')} ${t('basic.issue.vulnerabilities')}`);
    }

    if (summary.length === 0 && hasAttentionRequired) {
      summary.push(t('basic.issue.reviewRequired'));
    }

    return summary;
  }, [hasAttentionRequired, report.devices, t]);

  return (
    <div className="space-y-5">
      <GlassCard className="group relative overflow-hidden rounded-2xl border border-[var(--color-accent-border)] p-6 md:p-8">
        <div className="absolute -right-24 -top-24 h-64 w-64 rounded-full bg-[var(--color-accent)] opacity-[0.04] blur-[80px] transition-opacity duration-700 group-hover:opacity-[0.08]" />

        <p className="accent-text relative z-10 mb-6 text-xs font-bold uppercase tracking-widest">{t('basic.overview')}</p>

        <div className="relative z-10 flex flex-col gap-8 md:flex-row md:items-end md:justify-between">
          <div className="flex max-w-xl flex-1 flex-col items-start gap-4 text-left">
            <div className={`inline-flex h-14 w-14 items-center justify-center rounded-xl border shadow-lg ${hasAttentionRequired ? 'text-[var(--badge-danger-text)] border-[var(--badge-danger-border)] bg-[var(--badge-danger-bg)] shadow-[var(--badge-danger-border)]' : 'text-[var(--badge-success-text)] border-[var(--badge-success-border)] bg-[var(--badge-success-bg)] shadow-[var(--badge-success-border)]'}`}>
              {hasAttentionRequired ? <AlertTriangle size={26} /> : <ShieldCheck size={26} />}
            </div>
            <div>
              <h2 className={`text-3xl font-extrabold tracking-tight md:text-4xl ${hasAttentionRequired ? 'text-[var(--badge-danger-text)]' : 'text-[var(--badge-success-text)]'}`}>
                {hasAttentionRequired ? t('basic.attentionRequired') : t('basic.systemSecure')}
              </h2>
              <p className="text-soft mt-2 text-base font-medium">{report.summary.total} {t('basic.devicesScanned')}</p>
            </div>
          </div>

          <div className="flex flex-col items-start gap-3 md:items-end">
            <div className="flex flex-wrap gap-2 md:justify-end">
              <StatusBadge label={`${report.summary.compliant} ${t('basic.compliant')}`} tone="success" />
              <StatusBadge label={`${report.summary.warning} ${t('basic.warning')}`} tone="warning" />
              <StatusBadge label={`${report.summary.nonCompliant} ${t('basic.nonCompliant')}`} tone="danger" />
            </div>
          </div>
        </div>
      </GlassCard>

      <GlassCard className="rounded-2xl p-5">
        <h3 className="text-muted text-sm font-semibold uppercase tracking-wider">{t('basic.simpleIssues')}</h3>
        {issueSummary.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--badge-success-text)]">{t('basic.noMajorIssues')}</p>
        ) : (
          <ul className="text-main mt-3 space-y-2 text-sm">
            {issueSummary.map((issue) => (
              <li key={issue} className="surface-card rounded-lg border px-3 py-2">{issue}</li>
            ))}
          </ul>
        )}
      </GlassCard>
    </div>
  );
};

export default BasicDashboard;
