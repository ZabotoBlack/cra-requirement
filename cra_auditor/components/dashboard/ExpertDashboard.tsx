import React, { useState } from 'react';
import { Download } from 'lucide-react';
import Dashboard from '../Dashboard';
import DeviceList from '../DeviceList';
import GlassCard from '../ui/GlassCard';
import TechButton from '../ui/TechButton';
import { FrontendConfig, ScanReport } from '../../types';

interface ExpertDashboardProps {
  report: ScanReport;
  config: FrontendConfig | null;
  logs: string[];
}

const ExpertDashboard: React.FC<ExpertDashboardProps> = ({ report, config, logs }) => {
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
      <GlassCard className="rounded-2xl border border-[var(--color-accent-border)] p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="accent-text text-xs font-semibold uppercase tracking-widest">Expert Overview</p>
          <p className="text-muted text-xs">Full controls, raw data, and logs</p>
        </div>
      </GlassCard>

      <div className="flex justify-end">
        <TechButton variant="secondary" onClick={handleExportJson}>
          <Download size={14} />
          Export JSON
        </TechButton>
      </div>

      <Dashboard report={report} geminiEnabled={config?.gemini_enabled} nvdEnabled={config?.nvd_enabled} />

      <GlassCard className="rounded-2xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-muted text-sm font-semibold uppercase tracking-wider">Devices</h3>
          <TechButton variant="secondary" onClick={() => setShowDevices((previous) => !previous)}>
            {showDevices ? 'Collapse Devices' : 'Expand Devices'}
          </TechButton>
        </div>
        {showDevices && <div className="mt-4"><DeviceList devices={report.devices} /></div>}
      </GlassCard>

      <GlassCard className="rounded-2xl p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-muted text-sm font-semibold uppercase tracking-wider">Logs Console</h3>
          <TechButton variant="secondary" onClick={() => setExpandedLogs((previous) => !previous)}>
            {expandedLogs ? 'Collapse Logs' : 'Expand Logs'}
          </TechButton>
        </div>
        <div className={`terminal-panel overflow-auto rounded-xl border p-3 font-mono text-xs text-[var(--color-accent)] ${expandedLogs ? 'max-h-[840px]' : 'max-h-[280px]'}`}>
          {logs.length === 0 ? (
            <p className="text-soft">No logs captured yet.</p>
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
