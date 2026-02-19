import React, { useMemo, useState } from 'react';
import { useLanguage } from '../../LanguageContext';
import Dashboard from '../Dashboard';
import GlassCard from '../ui/GlassCard';
import StatusBadge from '../ui/StatusBadge';
import TechButton from '../ui/TechButton';
import { ScanReport, FrontendConfig, ComplianceStatus } from '../../types';

interface IntermediateDashboardProps {
  report: ScanReport;
  config: FrontendConfig | null;
}

const localizeStatus = (status: string, t: (key: 'status.compliant' | 'status.warningLabel' | 'status.nonCompliantLabel' | 'status.discovered') => string): string => {
  if (status === ComplianceStatus.COMPLIANT) return t('status.compliant');
  if (status === ComplianceStatus.WARNING) return t('status.warningLabel');
  if (status === ComplianceStatus.NON_COMPLIANT) return t('status.nonCompliantLabel');
  if (status === ComplianceStatus.DISCOVERED) return t('status.discovered');
  return status;
};

const IntermediateDashboard: React.FC<IntermediateDashboardProps> = ({ report, config }) => {
  const { t } = useLanguage();
  const [showDeviceDetails, setShowDeviceDetails] = useState(false);

  const rows = useMemo(() => {
    return report.devices.map((device) => ({
      key: `${device.mac}-${device.ip}`,
      hostname: device.hostname || t('intermediate.unknownHostname'),
      vendor: device.vendor || t('intermediate.unknownVendor'),
      status: device.status,
      details: `${device.openPorts?.length ?? 0} ${t('intermediate.openPorts')}${device.osMatch ? ` • ${device.osMatch}` : ''}${device.attackSurface ? ` • ${t('intermediate.attackSurface')} ${device.attackSurface.score}` : ''}`
    }));
  }, [report.devices, t]);

  return (
    <div className="space-y-5">
      <GlassCard className="rounded-2xl border border-[var(--color-accent-border)] p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="accent-text text-xs font-semibold uppercase tracking-widest">{t('intermediate.overview')}</p>
          <StatusBadge label={t('intermediate.standardVisibility')} tone="info" />
        </div>
      </GlassCard>

      <Dashboard report={report} geminiEnabled={config?.gemini_enabled} nvdEnabled={config?.nvd_enabled} />

      <GlassCard className="rounded-2xl p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-muted text-sm font-semibold uppercase tracking-wider">{t('intermediate.deviceOverview')}</h3>
          <TechButton variant="secondary" onClick={() => setShowDeviceDetails((prev) => !prev)}>
            {showDeviceDetails ? t('intermediate.hideAttackSurface') : t('intermediate.showAttackSurface')}
          </TechButton>
        </div>

        <div className="mt-4 space-y-2">
          {rows.map((row) => (
            <div key={row.key} className="surface-card flex flex-col gap-2 rounded-xl border px-3 py-2 text-sm md:flex-row md:items-center md:justify-between">
              <div className="min-w-0">
                <p className="text-main truncate font-semibold">{row.hostname}</p>
                <p className="text-soft truncate">{row.vendor}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge
                  label={localizeStatus(row.status, t)}
                  tone={row.status === ComplianceStatus.COMPLIANT ? 'success' : row.status === ComplianceStatus.WARNING ? 'warning' : row.status === ComplianceStatus.NON_COMPLIANT ? 'danger' : 'neutral'}
                />
                {showDeviceDetails && <span className="text-muted text-xs">{row.details}</span>}
              </div>
            </div>
          ))}
          {rows.length === 0 && <p className="text-soft text-sm">{t('intermediate.noDevices')}</p>}
        </div>
      </GlassCard>
    </div>
  );
};

export default IntermediateDashboard;
