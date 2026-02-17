import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ShieldCheck, ShieldQuestion, Sparkles } from 'lucide-react';
import { ComplianceStatus, ScanReport } from '../types';
import GlassCard from './ui/GlassCard';
import StatusBadge from './ui/StatusBadge';

interface DashboardProps {
  report: ScanReport;
  geminiEnabled?: boolean;
  nvdEnabled?: boolean;
}

const toneByStatus: Record<string, 'success' | 'warning' | 'danger' | 'neutral'> = {
  [ComplianceStatus.COMPLIANT]: 'success',
  [ComplianceStatus.WARNING]: 'warning',
  [ComplianceStatus.NON_COMPLIANT]: 'danger',
  [ComplianceStatus.DISCOVERED]: 'neutral'
};

const Dashboard: React.FC<DashboardProps> = ({ report, geminiEnabled, nvdEnabled }) => {
  const complianceScore = useMemo(() => {
    if (report.summary.total === 0) return 0;
    return Math.round((report.summary.compliant / report.summary.total) * 100);
  }, [report.summary]);

  const circumference = 2 * Math.PI * 52;
  const scoreOffset = circumference - (complianceScore / 100) * circumference;

  const vendorRisk = useMemo(() => {
    const vendorDataMap = new Map<string, number>();
    report.devices.forEach((device) => {
      if (device.status !== ComplianceStatus.COMPLIANT) {
        let vendor = device.vendor.split('(')[0].trim();
        if (vendor === 'Unknown' && device.osMatch !== 'Unknown') vendor = `Unknown (${device.osMatch})`;
        vendorDataMap.set(vendor, (vendorDataMap.get(vendor) || 0) + 1);
      }
    });

    return Array.from(vendorDataMap.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [report.devices]);

  const aiSummary = useMemo(() => {
    const critical = report.summary.nonCompliant;
    const warnings = report.summary.warning;
    const riskTier = critical > 0 ? 'HIGH' : warnings > 0 ? 'MODERATE' : 'LOW';
    return `Command assessment complete. Risk tier is ${riskTier}. ${critical} non-compliant and ${warnings} warning device${warnings === 1 ? '' : 's'} detected across ${report.summary.total} assets.`;
  }, [report.summary]);

  const [typedText, setTypedText] = useState('');

  useEffect(() => {
    setTypedText('');
    let i = 0;
    const timer = setInterval(() => {
      i += 1;
      setTypedText(aiSummary.slice(0, i));
      if (i >= aiSummary.length) clearInterval(timer);
    }, 18);

    return () => clearInterval(timer);
  }, [aiSummary]);

  const topVendors = vendorRisk.slice(0, 4);
  const maxVendorCount = Math.max(...topVendors.map(item => item.count), 1);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <GlassCard className="rounded-2xl p-4 xl:col-span-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-400">Total Devices</p>
              <h3 className="mt-1 text-3xl font-bold text-white">{report.summary.total}</h3>
              <p className="mt-1 text-xs text-slate-400">Target: {report.targetRange}</p>
            </div>
            <div className="rounded-full border border-cyan-400/35 bg-cyan-500/10 p-3 text-cyan-200">
              <ShieldQuestion size={22} />
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <StatusBadge label={`${report.summary.compliant} Compliant`} tone="success" />
            <StatusBadge label={`${report.summary.warning} Warning`} tone="warning" />
            <StatusBadge label={`${report.summary.nonCompliant} Non-Compliant`} tone="danger" />
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-400">AI Insight</p>
              <h3 className="mt-1 text-xl font-bold text-white">{geminiEnabled ? 'Operational' : 'Disabled'}</h3>
            </div>
            <Sparkles className={geminiEnabled ? 'text-violet-300 neon-text' : 'text-slate-500'} size={20} />
          </div>
          <div className="mt-3 flex gap-2">
            <StatusBadge label={geminiEnabled ? 'Gemini Online' : 'No API key'} tone={geminiEnabled ? 'success' : 'warning'} />
            <StatusBadge label={nvdEnabled ? 'NVD Synced' : 'NVD Offline'} tone={nvdEnabled ? 'success' : 'danger'} />
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-400">Warning Devices</p>
              <h3 className="mt-1 text-2xl font-bold text-amber-200">{report.summary.warning}</h3>
            </div>
            <AlertTriangle size={20} className="text-amber-300" />
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-400">Compliant Devices</p>
              <h3 className="mt-1 text-2xl font-bold text-emerald-200">{report.summary.compliant}</h3>
            </div>
            <ShieldCheck size={20} className="text-emerald-300" />
          </div>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <GlassCard className="rounded-2xl p-5 xl:col-span-1">
          <p className="text-xs uppercase tracking-wider text-slate-400">Compliance Score</p>
          <div className="mt-4 flex items-center justify-center">
            <div className="relative h-44 w-44">
              <svg viewBox="0 0 140 140" className="h-full w-full -rotate-90">
                <circle cx="70" cy="70" r="52" fill="transparent" stroke="rgba(148,163,184,0.15)" strokeWidth="12" />
                <circle
                  cx="70"
                  cy="70"
                  r="52"
                  fill="transparent"
                  stroke={complianceScore >= 80 ? '#34d399' : complianceScore >= 50 ? '#fbbf24' : '#fb7185'}
                  strokeWidth="12"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={scoreOffset}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <p className="font-mono text-4xl font-bold text-white">{complianceScore}%</p>
                <p className="text-xs uppercase tracking-widest text-slate-400">Compliance</p>
              </div>
            </div>
          </div>
          <p className="mt-2 text-center text-xs text-slate-400">Score is based on compliant devices versus scanned inventory.</p>
        </GlassCard>

        <GlassCard className="rounded-2xl p-5 xl:col-span-1">
          <p className="text-xs uppercase tracking-wider text-slate-400">Risk Analysis</p>
          <div className="mt-4 space-y-3">
            {topVendors.length > 0 ? topVendors.map((item) => {
              const ratio = item.count / maxVendorCount;
              const width = Math.max(16, Math.round(ratio * 100));
              const tone = item.count >= 3 ? 'danger' : item.count === 2 ? 'warning' : 'info';
              return (
                <div key={item.name}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="truncate text-slate-300">{item.name}</span>
                    <StatusBadge label={`${item.count} risk`} tone={tone} />
                  </div>
                  <div className="h-2 rounded-full bg-slate-800">
                    <div
                      className="h-2 rounded-full"
                      style={{
                        width: `${width}%`,
                        background: 'linear-gradient(90deg, rgba(244,63,94,0.95), rgba(251,191,36,0.8), rgba(34,211,238,0.65))'
                      }}
                    />
                  </div>
                </div>
              );
            }) : (
              <p className="pt-8 text-center text-sm text-slate-500">No elevated vendor risk detected.</p>
            )}
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-5 xl:col-span-1">
          <p className="text-xs uppercase tracking-wider text-slate-400">Message from Command</p>
          <div className="mt-3 rounded-xl border border-violet-400/25 bg-violet-500/10 p-4">
            <p className="typing-cursor min-h-[110px] text-sm leading-relaxed text-violet-100">
              {typedText}
            </p>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {Object.entries(report.summary)
              .filter(([key]) => key !== 'total')
              .map(([key, value]) => (
                <StatusBadge key={key} label={`${key} ${value}`} tone={toneByStatus[key === 'compliant' ? ComplianceStatus.COMPLIANT : key === 'warning' ? ComplianceStatus.WARNING : ComplianceStatus.NON_COMPLIANT]} />
              ))}
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

export default Dashboard;
