import React, { useMemo, useState } from 'react';
import { Bot, ChevronDown, ChevronUp, Cpu, FileText, Info, Lock, Network, Router, Shield } from 'lucide-react';
import { ComplianceStatus, Device, UserMode } from '../types';
import { useLanguage } from '../LanguageContext';
import { getRemediationAdvice } from '../services/geminiService';
import { localizeStatus } from '../utils/status';
import GlassCard from './ui/GlassCard';
import StatusBadge from './ui/StatusBadge';
import TechButton from './ui/TechButton';
import { CheckCircle2, AlertTriangle, Minus, XCircle } from 'lucide-react';

type DossierTab = 'checks' | 'raw' | 'ai';

interface DeviceListProps {
  devices: Device[];
  userMode?: UserMode;
}

/** Return status dot color classes aligned with compliance severity. */
const statusDotClass = (status: string) => {
  if (status === ComplianceStatus.COMPLIANT) return 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.9)]';
  if (status === ComplianceStatus.WARNING) return 'bg-amber-400 shadow-[0_0_12px_rgba(251,191,36,0.85)]';
  if (status === ComplianceStatus.NON_COMPLIANT) return 'bg-rose-400 shadow-[0_0_12px_rgba(251,113,133,0.9)]';
  if (status === ComplianceStatus.DISCOVERED) return 'bg-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.85)]';
  return 'bg-slate-400 shadow-[0_0_12px_rgba(148,163,184,0.8)]';
};

/** Render small status indicator for table cells */
const StatusIcon: React.FC<{ passed?: boolean; details?: string }> = ({ passed, details }) => {
  const { t } = useLanguage();

  if (passed === undefined) {
    return (
      <div className="flex justify-center" title={t('deviceList.check.notEvaluated')}>
        <Minus size={16} className="text-slate-500" />
      </div>
    );
  }

  if (passed) {
    return (
      <div className="flex justify-center group relative cursor-help">
        <CheckCircle2 size={16} className="text-[var(--badge-success-text)] drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]" />
        {details && (
          <span
            role="tooltip"
            className="surface-elevated text-main pointer-events-none absolute bottom-full mb-2 hidden w-48 -translate-x-1/2 left-1/2 rounded-lg border px-3 py-2 text-xs leading-relaxed group-hover:block z-10"
          >
            {details}
          </span>
        )}
      </div>
    );
  }

  const isWarning = details?.toLowerCase().includes('warning') || false;

  return (
    <div className="flex justify-center group relative cursor-help">
      {isWarning ? (
        <AlertTriangle size={16} className="text-[var(--badge-warning-text)] drop-shadow-[0_0_8px_rgba(251,191,36,0.5)]" />
      ) : (
        <XCircle size={16} className="text-[var(--badge-danger-text)] drop-shadow-[0_0_8px_rgba(251,113,133,0.5)]" />
      )}
      {details && (
        <span
          role="tooltip"
          className="surface-elevated text-main pointer-events-none absolute bottom-full mb-2 hidden w-48 -translate-x-1/2 left-1/2 rounded-lg border px-3 py-2 text-xs leading-relaxed group-hover:block z-10"
        >
          {details}
        </span>
      )}
    </div>
  );
};

const CheckHeader: React.FC<{ label: string; requirement: string }> = ({ label, requirement }) => {
  const { t } = useLanguage();

  return (
    <div className="inline-flex items-center justify-center gap-1.5 whitespace-nowrap">
      <span>{label}</span>
      <span className="group relative inline-flex">
        <button
          type="button"
          aria-label={t('dashboard.craRequirementInfo')}
          title={t('dashboard.craRequirementInfo')}
          className="text-soft hover:text-main inline-flex h-4 w-4 items-center justify-center rounded-full border border-[var(--border-subtle)] transition"
        >
          <Info size={10} aria-hidden="true" />
        </button>
        <span
          role="tooltip"
          className="surface-elevated text-main pointer-events-none absolute left-1/2 top-full z-10 mt-2 hidden w-72 -translate-x-1/2 rounded-lg border px-3 py-2 text-left text-xs normal-case leading-relaxed tracking-normal group-hover:block group-focus-within:block"
        >
          {requirement}
        </span>
      </span>
    </div>
  );
};

const DeviceDossier: React.FC<{ device: Device; userMode?: UserMode }> = ({ device, userMode = 'intermediate' }) => {
  const { t, language } = useLanguage();
  const [tab, setTab] = useState<DossierTab>('checks');
  const [loadingAdvice, setLoadingAdvice] = useState(false);
  const [advice, setAdvice] = useState<string | null>(null);

  const rawDataPreview = useMemo(() => {
    const parsedTimestamp = new Date(device.lastScanned);
    if (Number.isNaN(parsedTimestamp.getTime())) {
      return device;
    }

    return {
      ...device,
      lastScanned: parsedTimestamp.toLocaleString()
    };
  }, [device]);

  const checks = [
    { key: t('deviceList.check.secureDefaults'), passed: device.checks?.secureByDefault?.passed, details: device.checks?.secureByDefault?.details, icon: <Lock size={14} />, requirement: t('dashboard.cra.req.secureDefaults') },
    { key: t('deviceList.check.encryption'), passed: device.checks?.dataConfidentiality?.passed, details: device.checks?.dataConfidentiality?.details, icon: <Shield size={14} />, requirement: t('dashboard.cra.req.encryption') },
    { key: t('deviceList.check.httpsOnly'), passed: device.checks?.httpsOnlyManagement?.passed, details: device.checks?.httpsOnlyManagement?.details, icon: <Shield size={14} />, requirement: t('dashboard.cra.req.httpsOnly') },
    { key: t('deviceList.check.vulnerabilities'), passed: device.checks?.vulnerabilities?.passed, details: device.checks?.vulnerabilities?.details, icon: <Cpu size={14} />, requirement: t('dashboard.cra.req.vulnerabilities') },
    { key: t('deviceList.check.sbom'), passed: device.checks?.sbomCompliance?.passed, details: device.checks?.sbomCompliance?.details, icon: <FileText size={14} />, requirement: t('dashboard.cra.req.sbom') },
    { key: t('deviceList.check.firmware'), passed: device.checks?.firmwareTracking?.passed, details: device.checks?.firmwareTracking?.details, icon: <FileText size={14} />, requirement: t('dashboard.cra.req.firmware') },
    { key: t('deviceList.check.secTxt'), passed: device.checks?.securityTxt?.passed, details: device.checks?.securityTxt?.details, icon: <FileText size={14} />, requirement: t('dashboard.cra.req.securityTxt') },
    { key: t('deviceList.check.securityLogging'), passed: device.checks?.securityLogging?.passed, details: device.checks?.securityLogging?.details, icon: <Network size={14} />, requirement: t('dashboard.cra.req.securityLogging') },
  ];

  const handleAnalyze = async () => {
    if (advice) {
      setTab('ai');
      return;
    }

    setLoadingAdvice(true);
    const result = await getRemediationAdvice(device, {
      localizedStatus: localizeStatus(device.status, t),
      responseLanguage: language,
      noApiKey: t('gemini.error.noApiKey'),
      requestFailed: t('gemini.error.requestFailed'),
      noAdvice: t('gemini.error.noAdvice')
    });
    setAdvice(result);
    setLoadingAdvice(false);
    setTab('ai');
  };

  const tabButton = (id: DossierTab, label: string) => (
    <button
      onClick={() => setTab(id)}
      className={`rounded-lg border px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${tab === id
        ? 'border-cyan-400/50 bg-cyan-500/20 text-cyan-100'
        : 'border-slate-700 bg-slate-800/70 text-slate-300 hover:text-white'
        }`}
    >
      {label}
    </button>
  );

  return (
    <div className="rounded-xl border border-slate-700/70 bg-slate-950/55 p-5">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h4 className="text-sm font-bold text-white">{t('deviceList.dossierTitle')}</h4>
          <p className="font-mono text-sm text-slate-300">{device.ip} · {device.mac}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {tabButton('checks', t('deviceList.tab.securityChecks'))}
          {userMode === 'expert' && tabButton('raw', t('deviceList.tab.rawData'))}
          {userMode === 'expert' && tabButton('ai', t('deviceList.tab.aiRemediation'))}
          {userMode === 'expert' && device.status !== ComplianceStatus.COMPLIANT && (
            <TechButton variant="primary" className="px-3 py-1.5 text-xs" onClick={handleAnalyze} disabled={loadingAdvice}>
              <Bot size={14} />
              {loadingAdvice ? t('deviceList.actions.analyzing') : t('deviceList.actions.analyze')}
            </TechButton>
          )}
        </div>
      </div>

      {tab === 'checks' && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3 xl:grid-cols-5">
          {checks.map((check) => (
            <div key={check.key} className="rounded-xl border border-slate-700/70 bg-slate-900/70 p-4">
              <div className="mb-2 flex items-center justify-between text-slate-300">
                <span className="inline-flex items-center gap-1.5 text-sm font-semibold uppercase tracking-wider">{check.icon}{check.key}</span>
                <span className="group relative inline-flex">
                  <button
                    type="button"
                    aria-label={t('dashboard.craRequirementInfo')}
                    title={t('dashboard.craRequirementInfo')}
                    className="text-soft hover:text-main inline-flex h-5 w-5 items-center justify-center rounded-full border border-[var(--border-subtle)] transition"
                  >
                    <Info size={11} aria-hidden="true" />
                  </button>
                  <span
                    role="tooltip"
                    className="surface-elevated text-main pointer-events-none absolute right-0 top-full z-10 mt-2 hidden w-80 rounded-lg border px-3 py-2 text-xs normal-case leading-relaxed tracking-normal group-hover:block group-focus-within:block"
                  >
                    {check.requirement}
                  </span>
                </span>
              </div>
              <StatusBadge
                label={check.passed === undefined ? t('deviceList.check.notEvaluated') : check.passed ? t('deviceList.check.pass') : t('deviceList.check.attention')}
                tone={check.passed === undefined ? 'neutral' : check.passed ? 'success' : 'warning'}
              />
              <p className="mt-2 text-sm leading-relaxed text-slate-300">{check.details || t('deviceList.check.noData')}</p>
            </div>
          ))}
        </div>
      )}

      {tab === 'raw' && (
        <pre className="max-h-[340px] overflow-auto rounded-xl border border-slate-700/80 bg-slate-900/80 p-4 font-mono text-sm leading-relaxed text-cyan-100">
          {JSON.stringify(rawDataPreview, null, 2)}
        </pre>
      )}

      {tab === 'ai' && (
        <div className="rounded-xl border border-cyan-400/30 bg-cyan-500/10 p-3">
          {advice ? (
            <p className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-cyan-100">{advice}</p>
          ) : (
            <p className="text-sm text-slate-300">{t('deviceList.ai.empty')}</p>
          )}
        </div>
      )}
    </div>
  );
};

const DeviceRow: React.FC<{ device: Device; rowId: string; userMode?: UserMode }> = ({ device, rowId, userMode }) => {
  const { t } = useLanguage();
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        className={`cursor-pointer border-b border-slate-800/70 transition-colors hover:bg-slate-900/45 ${expanded ? 'bg-slate-900/55' : ''}`}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-3">
            <div className="rounded-lg border border-slate-700 bg-slate-900/85 p-2 text-cyan-200">
              <Router size={16} />
            </div>
            <div>
              <p className={`font-medium ${device.hostname ? 'text-white' : 'text-slate-500 italic'}`}>
                {device.hostname || t('deviceList.unknownHostname')}
              </p>
              <p className="text-sm text-slate-300">{device.osMatch || t('deviceList.unknownOs')}</p>
            </div>
          </div>
        </td>
        <td className="px-4 py-3">
          <p className="font-mono text-sm text-cyan-100">{device.ip}</p>
          <p className="font-mono text-sm text-slate-300">{device.mac}</p>
        </td>
        <td className="px-4 py-3">
          <StatusBadge label={device.vendor || t('deviceList.unknownVendor')} tone="info" />
        </td>
        <td className="px-4 py-3">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/75 px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-slate-100 whitespace-nowrap">
            <span className={`h-2.5 w-2.5 rounded-full ${statusDotClass(device.status)}`} />
            {localizeStatus(device.status, t)}
          </div>
        </td>
        <td className="px-4 py-3 text-right text-slate-400 border-l border-slate-700/50">
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </td>
      </tr>

      {expanded && (
        <tr id={rowId}>
          <td colSpan={5} className="px-4 py-4 bg-slate-900/20">
            <DeviceDossier device={device} userMode={userMode} />
          </td>
        </tr>
      )}
    </>
  );
};

const DeviceList: React.FC<DeviceListProps> = ({ devices, userMode }) => {
  const { t } = useLanguage();
  const [filterText, setFilterText] = useState('');
  const [sortConfig, setSortConfig] = useState<{ key: keyof Device; direction: 'asc' | 'desc' } | null>(null);

  const handleSort = (key: keyof Device) => {
    // Toggle ascending/descending sorting for the selected column.
    let direction: 'asc' | 'desc' = 'asc';
    if (sortConfig && sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const filteredDevices = useMemo(() => {
    const text = filterText.toLowerCase();
    return devices.filter((device) =>
      device.hostname.toLowerCase().includes(text) ||
      device.ip.toLowerCase().includes(text) ||
      device.vendor.toLowerCase().includes(text) ||
      device.mac.toLowerCase().includes(text)
    );
  }, [devices, filterText]);

  const compareIPs = (ipA: string, ipB: string) => {
    // Numeric IPv4 comparison keeps table ordering stable by network order.
    const numA = ipA.split('.').map(Number);
    const numB = ipB.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if (numA[i] !== numB[i]) return numA[i] - numB[i];
    }
    return 0;
  };

  const sortedDevices = useMemo(() => {
    if (!sortConfig) return filteredDevices;
    return [...filteredDevices].sort((a, b) => {
      if (sortConfig.key === 'ip') {
        return sortConfig.direction === 'asc'
          ? compareIPs(a.ip, b.ip)
          : compareIPs(b.ip, a.ip);
      }

      const valueA = String(a[sortConfig.key] ?? '');
      const valueB = String(b[sortConfig.key] ?? '');
      return sortConfig.direction === 'asc'
        ? valueA.localeCompare(valueB)
        : valueB.localeCompare(valueA);
    });
  }, [filteredDevices, sortConfig]);

  const sortIcon = (column: keyof Device) => {
    // Render active sorting indicator per selected column.
    if (sortConfig?.key !== column) return <ChevronDown size={14} className="inline-block opacity-20" />;
    return sortConfig.direction === 'asc'
      ? <ChevronUp size={14} className="inline-block text-cyan-300" />
      : <ChevronDown size={14} className="inline-block text-cyan-300" />;
  };

  return (
    <div className="space-y-4">
      <GlassCard data-tour-id="devices-list-panel" className="rounded-2xl p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <input
            type="text"
            placeholder={t('deviceList.filterPlaceholder')}
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900/85 px-3 py-2 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
          />
          <StatusBadge label={`${sortedDevices.length}/${devices.length} ${t('deviceList.visible')}`} tone="neutral" />
        </div>
      </GlassCard>

      <GlassCard className="overflow-hidden rounded-2xl p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] text-left">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-xs uppercase tracking-wider text-slate-300">
                <th className="px-4 py-3 cursor-pointer" onClick={() => handleSort('hostname')}>{t('deviceList.col.device')} {sortIcon('hostname')}</th>
                <th className="px-4 py-3 cursor-pointer" onClick={() => handleSort('ip')}>{t('deviceList.col.ipMac')} {sortIcon('ip')}</th>
                <th className="px-4 py-3 cursor-pointer" onClick={() => handleSort('vendor')}>{t('deviceList.col.vendor')} {sortIcon('vendor')}</th>
                <th className="px-4 py-3 cursor-pointer whitespace-nowrap" onClick={() => handleSort('status')}>{t('deviceList.col.status')} {sortIcon('status')}</th>
                <th className="px-4 py-3 border-l border-slate-700/50" />
              </tr>
            </thead>
            <tbody>
              {sortedDevices.map((device, idx) => (
                <DeviceRow key={`${device.mac}-${idx}`} device={device} rowId={`device-${idx}`} userMode={userMode} />
              ))}
              {sortedDevices.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-6 py-14 text-center text-sm text-slate-500">
                    {devices.length === 0 ? t('deviceList.empty.noDevices') : t('deviceList.empty.noMatch')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
};

export default DeviceList;
