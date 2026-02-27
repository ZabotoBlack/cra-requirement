import React, { useState } from 'react';
import { Download } from 'lucide-react';
import Dashboard from '../Dashboard';
import DeviceList from '../DeviceList';
import GlassCard from '../ui/GlassCard';
import TechButton from '../ui/TechButton';
import { useLanguage } from '../../LanguageContext';
import { FrontendConfig, ScanReport } from '../../types';

interface ExpertDashboardProps {
  report: ScanReport;
  config: FrontendConfig | null;
  logs: string[];
}

const ExpertDashboard: React.FC<ExpertDashboardProps> = ({ report, config, logs }) => {
  const { t } = useLanguage();
  const [showDevices, setShowDevices] = useState(true);
  const [expandedLogs, setExpandedLogs] = useState(false);

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `cra-report-${new Date(report.timestamp).toISOString().replace(/[:.]/g, '-')}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <GlassCard className="group relative overflow-hidden rounded-2xl border border-[var(--color-accent-border)] p-6 md:p-8">
        <div className="absolute -right-20 -top-24 h-72 w-72 rounded-full bg-[var(--color-accent)] opacity-[0.05] blur-[90px] transition-opacity duration-700 group-hover:opacity-[0.09]" />

        <div className="relative z-10 flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="accent-text mb-2 text-xs font-bold uppercase tracking-widest">{t('expert.overview')}</p>
            <h2 className="text-3xl font-extrabold tracking-tight text-main md:text-4xl">{t('expert.securityOperations')}</h2>
            <p className="text-soft mt-2 text-sm font-medium">{t('expert.subtitle')}</p>
          </div>
          <div className="flex flex-col items-start md:items-end">
            <TechButton variant="secondary" onClick={handleExportJson} className="border-[var(--color-accent-border)] hover:bg-[var(--color-accent-soft)]">
              <Download size={14} />
              {t('expert.exportJson')}
            </TechButton>
          </div>
        </div>
      </GlassCard>

      <Dashboard report={report} geminiEnabled={config?.gemini_enabled} nvdEnabled={config?.nvd_enabled} />

      <GlassCard className="rounded-2xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-muted text-sm font-semibold uppercase tracking-wider">{t('expert.devices')}</h3>
          <TechButton variant="secondary" onClick={() => setShowDevices((previous) => !previous)}>
            {showDevices ? t('expert.collapseDevices') : t('expert.expandDevices')}
          </TechButton>
        </div>
        {showDevices && <div className="mt-4"><DeviceList devices={report.devices} userMode="expert" /></div>}
      </GlassCard>

      <GlassCard className="rounded-2xl p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-muted text-sm font-semibold uppercase tracking-wider">{t('expert.logsConsole')}</h3>
          <TechButton variant="secondary" onClick={() => setExpandedLogs((previous) => !previous)}>
            {expandedLogs ? t('expert.collapseLogs') : t('expert.expandLogs')}
          </TechButton>
        </div>
        <div className={`terminal-panel overflow-auto rounded-xl border p-3 font-mono text-xs text-[var(--color-accent)] ${expandedLogs ? 'max-h-[840px]' : 'max-h-[280px]'}`}>
          {logs.length === 0 ? (
            <p className="text-soft">{t('expert.noLogs')}</p>
          ) : (
            logs.map((line, index) => (
              <div key={`${line}-${index}`} className="whitespace-pre-wrap break-words py-0.5">
                {line}
              </div>
            ))
          )}
        </div>
      </GlassCard>
    </div>
  );
};

export default ExpertDashboard;
