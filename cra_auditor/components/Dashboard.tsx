import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ShieldCheck, ShieldQuestion, Sparkles } from 'lucide-react';
import { ComplianceStatus, ScanReport } from '../types';
import { useLanguage } from '../LanguageContext';
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
  const { t } = useLanguage();
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
    const riskTier = critical > 0
      ? t('dashboard.riskTier.high')
      : warnings > 0
        ? t('dashboard.riskTier.moderate')
        : t('dashboard.riskTier.low');
    return `${t('dashboard.commandAssessmentComplete')} ${t('dashboard.riskTierIs')} ${riskTier}. ${critical} ${t('dashboard.nonCompliantLower')} ${t('dashboard.and')} ${warnings} ${t('dashboard.warningDevices')} ${t('dashboard.detectedAcross')} ${report.summary.total} ${t('dashboard.assets')}.`;
  }, [report.summary, t]);

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
        <GlassCard className="rounded-2xl p-5 xl:col-span-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted text-sm uppercase tracking-wider">{t('dashboard.totalDevices')}</p>
              <h3 className="text-main mt-1 text-3xl font-bold">{report.summary.total}</h3>
              <p className="text-muted mt-1 text-sm">{t('dashboard.target')}: {report.targetRange}</p>
            </div>
            <div className="accent-ring rounded-full border p-3">
              <ShieldQuestion size={22} />
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <StatusBadge label={`${report.summary.compliant} ${t('dashboard.compliant')}`} tone="success" />
            <StatusBadge label={`${report.summary.warning} ${t('dashboard.warning')}`} tone="warning" />
            <StatusBadge label={`${report.summary.nonCompliant} ${t('dashboard.nonCompliant')}`} tone="danger" />
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted text-sm uppercase tracking-wider">{t('dashboard.aiInsight')}</p>
              <h3 className="text-main mt-1 text-xl font-bold">{geminiEnabled ? t('dashboard.operational') : t('dashboard.disabled')}</h3>
            </div>
            <Sparkles className={geminiEnabled ? 'accent-text neon-text' : 'text-soft'} size={20} />
          </div>
          <div className="mt-3 flex gap-2">
            <StatusBadge label={geminiEnabled ? t('dashboard.geminiOnline') : t('dashboard.noApiKey')} tone={geminiEnabled ? 'success' : 'warning'} />
            <StatusBadge label={nvdEnabled ? t('dashboard.nvdSynced') : t('dashboard.nvdOffline')} tone={nvdEnabled ? 'success' : 'danger'} />
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted text-sm uppercase tracking-wider">{t('dashboard.warningDevicesTitle')}</p>
              <h3 className="mt-1 text-2xl font-bold text-[var(--badge-warning-text)]">{report.summary.warning}</h3>
            </div>
            <AlertTriangle size={20} className="text-[var(--badge-warning-text)]" />
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-muted text-sm uppercase tracking-wider">{t('dashboard.compliantDevicesTitle')}</p>
              <h3 className="mt-1 text-2xl font-bold text-[var(--badge-success-text)]">{report.summary.compliant}</h3>
            </div>
            <ShieldCheck size={20} className="text-[var(--badge-success-text)]" />
          </div>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <GlassCard className="rounded-2xl p-5 xl:col-span-1">
          <p className="text-muted text-sm uppercase tracking-wider">{t('dashboard.complianceScore')}</p>
          <div className="mt-4 flex items-center justify-center">
            <div className="relative h-44 w-44">
              <svg viewBox="0 0 140 140" className="h-full w-full -rotate-90">
                <circle cx="70" cy="70" r="52" fill="transparent" stroke="var(--border-subtle)" strokeWidth="12" />
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
                <p className="text-main font-mono text-4xl font-bold">{complianceScore}%</p>
                <p className="text-muted text-sm uppercase tracking-widest">{t('dashboard.compliance')}</p>
              </div>
            </div>
          </div>
          <p className="text-muted mt-2 text-center text-sm">{t('dashboard.scoreExplanation')}</p>
        </GlassCard>

        <GlassCard className="rounded-2xl p-5 xl:col-span-1">
          <p className="text-muted text-sm uppercase tracking-wider">{t('dashboard.riskAnalysis')}</p>
          <div className="mt-4 space-y-3">
            {topVendors.length > 0 ? topVendors.map((item) => {
              const ratio = item.count / maxVendorCount;
              const width = Math.max(16, Math.round(ratio * 100));
              const tone = item.count >= 3 ? 'danger' : item.count === 2 ? 'warning' : 'info';
              return (
                <div key={item.name}>
                  <div className="mb-1 flex items-center justify-between text-sm">
                    <span className="text-muted truncate">{item.name}</span>
                    <StatusBadge label={`${item.count} ${t('dashboard.risk')}`} tone={tone} />
                  </div>
                  <div className="h-2 rounded-full bg-[var(--border-subtle)]">
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
              <p className="text-soft pt-8 text-center text-sm">{t('dashboard.noElevatedVendorRisk')}</p>
            )}
          </div>
        </GlassCard>

        <GlassCard className="rounded-2xl p-5 xl:col-span-1">
          <p className="text-muted text-sm uppercase tracking-wider">{t('dashboard.messageFromCommand')}</p>
          <div className="accent-ring mt-3 rounded-xl border p-4">
            <p className="typing-cursor min-h-[110px] text-main text-sm leading-relaxed">
              {typedText}
            </p>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {Object.entries(report.summary)
              .filter(([key]) => key !== 'total')
              .map(([key, value]) => (
                <StatusBadge key={key} label={`${key === 'compliant' ? t('dashboard.compliant') : key === 'warning' ? t('dashboard.warning') : t('dashboard.nonCompliant')} ${value}`} tone={toneByStatus[key === 'compliant' ? ComplianceStatus.COMPLIANT : key === 'warning' ? ComplianceStatus.WARNING : ComplianceStatus.NON_COMPLIANT]} />
              ))}
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

export default Dashboard;
