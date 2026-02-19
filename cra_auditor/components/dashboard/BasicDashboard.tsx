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
      <GlassCard className="rounded-2xl border border-[var(--color-accent-border)] p-6">
        <p className="accent-text mb-4 text-xs font-semibold uppercase tracking-widest">{t('basic.overview')}</p>
        <div className="flex flex-col items-center gap-3 text-center">
          <div className={`inline-flex h-16 w-16 items-center justify-center rounded-full border ${hasAttentionRequired ? 'text-[var(--badge-danger-text)] border-[var(--badge-danger-border)] bg-[var(--badge-danger-bg)]' : 'text-[var(--badge-success-text)] border-[var(--badge-success-border)] bg-[var(--badge-success-bg)]'}`}>
            {hasAttentionRequired ? <AlertTriangle size={30} /> : <ShieldCheck size={30} />}
          </div>
          <h2 className={`text-3xl font-bold ${hasAttentionRequired ? 'text-[var(--badge-danger-text)]' : 'text-[var(--badge-success-text)]'}`}>
            {hasAttentionRequired ? t('basic.attentionRequired') : t('basic.systemSecure')}
          </h2>
          <p className="text-muted">{report.summary.total} {t('basic.devicesScanned')}</p>
          <div className="flex flex-wrap justify-center gap-2">
            <StatusBadge label={`${report.summary.compliant} ${t('basic.compliant')}`} tone="success" />
            <StatusBadge label={`${report.summary.warning} ${t('basic.warning')}`} tone="warning" />
            <StatusBadge label={`${report.summary.nonCompliant} ${t('basic.nonCompliant')}`} tone="danger" />
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
