import React, { useMemo } from 'react';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { ScanReport } from '../../types';
import GlassCard from '../ui/GlassCard';
import StatusBadge from '../ui/StatusBadge';

interface BasicDashboardProps {
  report: ScanReport;
}

const BasicDashboard: React.FC<BasicDashboardProps> = ({ report }) => {
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
      summary.push(`${defaultPasswordCount} device${defaultPasswordCount === 1 ? '' : 's'} may still use default passwords`);
    }
    if (updateCount > 0) {
      summary.push(`${updateCount} device${updateCount === 1 ? '' : 's'} need firmware updates`);
    }
    if (vulnerabilityCount > 0) {
      summary.push(`${vulnerabilityCount} device${vulnerabilityCount === 1 ? '' : 's'} have known vulnerabilities`);
    }

    if (summary.length === 0 && hasAttentionRequired) {
      summary.push('Some devices need review based on compliance checks.');
    }

    return summary;
  }, [hasAttentionRequired, report.devices]);

  return (
    <div className="space-y-5">
      <GlassCard className="rounded-2xl border border-emerald-400/25 bg-emerald-500/5 p-6">
        <p className="mb-4 text-xs font-semibold uppercase tracking-widest text-emerald-200">End User Overview</p>
        <div className="flex flex-col items-center gap-3 text-center">
          <div className={`inline-flex h-16 w-16 items-center justify-center rounded-full border ${hasAttentionRequired ? 'border-rose-400/40 bg-rose-500/15 text-rose-200' : 'border-emerald-400/40 bg-emerald-500/15 text-emerald-200'}`}>
            {hasAttentionRequired ? <AlertTriangle size={30} /> : <ShieldCheck size={30} />}
          </div>
          <h2 className={`text-3xl font-bold ${hasAttentionRequired ? 'text-rose-200' : 'text-emerald-200'}`}>
            {hasAttentionRequired ? 'Attention Required' : 'System Secure'}
          </h2>
          <p className="text-slate-300">{report.summary.total} devices scanned</p>
          <div className="flex flex-wrap justify-center gap-2">
            <StatusBadge label={`${report.summary.compliant} Compliant`} tone="success" />
            <StatusBadge label={`${report.summary.warning} Warning`} tone="warning" />
            <StatusBadge label={`${report.summary.nonCompliant} Non-Compliant`} tone="danger" />
          </div>
        </div>
      </GlassCard>

      <GlassCard className="rounded-2xl p-5">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">Simple Issues</h3>
        {issueSummary.length === 0 ? (
          <p className="mt-3 text-sm text-emerald-200">No major issues detected in this scan.</p>
        ) : (
          <ul className="mt-3 space-y-2 text-sm text-slate-200">
            {issueSummary.map((issue) => (
              <li key={issue} className="rounded-lg border border-slate-700/70 bg-slate-900/70 px-3 py-2">{issue}</li>
            ))}
          </ul>
        )}
      </GlassCard>
    </div>
  );
};

export default BasicDashboard;
