import React, { useMemo, useState } from 'react';
import Dashboard from '../Dashboard';
import GlassCard from '../ui/GlassCard';
import StatusBadge from '../ui/StatusBadge';
import TechButton from '../ui/TechButton';
import { ScanReport, FrontendConfig } from '../../types';

interface IntermediateDashboardProps {
  report: ScanReport;
  config: FrontendConfig | null;
}

const IntermediateDashboard: React.FC<IntermediateDashboardProps> = ({ report, config }) => {
  const [showDeviceDetails, setShowDeviceDetails] = useState(false);

  const rows = useMemo(() => {
    return report.devices.map((device) => ({
      key: `${device.mac}-${device.ip}`,
      hostname: device.hostname || 'Unknown Hostname',
      vendor: device.vendor || 'Unknown',
      status: device.status,
      details: `${device.openPorts?.length ?? 0} open ports${device.osMatch ? ` • ${device.osMatch}` : ''}${device.attackSurface ? ` • Attack Surface ${device.attackSurface.score}` : ''}`
    }));
  }, [report.devices]);

  return (
    <div className="space-y-5">
      <GlassCard className="rounded-2xl border border-cyan-400/25 bg-cyan-500/5 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-semibold uppercase tracking-widest text-cyan-200">Intermediate Overview</p>
          <StatusBadge label="Standard Visibility" tone="info" />
        </div>
      </GlassCard>

      <Dashboard report={report} geminiEnabled={config?.gemini_enabled} nvdEnabled={config?.nvd_enabled} />

      <GlassCard className="rounded-2xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">Device Overview</h3>
          <TechButton variant="secondary" onClick={() => setShowDeviceDetails((prev) => !prev)}>
            {showDeviceDetails ? 'Hide Attack Surface Details' : 'Show Attack Surface Details'}
          </TechButton>
        </div>

        <div className="mt-4 space-y-2">
          {rows.map((row) => (
            <div key={row.key} className="flex flex-col gap-2 rounded-xl border border-slate-700/70 bg-slate-900/70 px-3 py-2 text-sm md:flex-row md:items-center md:justify-between">
              <div className="min-w-0">
                <p className="truncate font-semibold text-white">{row.hostname}</p>
                <p className="truncate text-slate-400">{row.vendor}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge label={row.status} tone={row.status === 'Compliant' ? 'success' : row.status === 'Warning' ? 'warning' : row.status === 'Non-Compliant' ? 'danger' : 'neutral'} />
                {showDeviceDetails && <span className="text-xs text-slate-300">{row.details}</span>}
              </div>
            </div>
          ))}
          {rows.length === 0 && <p className="text-sm text-slate-400">No devices in this report.</p>}
        </div>
      </GlassCard>
    </div>
  );
};

export default IntermediateDashboard;
