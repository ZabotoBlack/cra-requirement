import { Activity, AlertTriangle, ChevronsLeft, ChevronsRight, History, LayoutDashboard, List, Moon, Play, RotateCw, Settings, ShieldCheck, Sun, X } from 'lucide-react';
import React, { useEffect, useState, useRef, useCallback } from 'react';
import DeviceList from './components/DeviceList';
import HistoryView from './components/HistoryView';
import BasicDashboard from './components/dashboard/BasicDashboard';
import IntermediateDashboard from './components/dashboard/IntermediateDashboard';
import ExpertDashboard from './components/dashboard/ExpertDashboard';
import SettingsModal from './components/SettingsModal';
import LanguageSelector from './components/LanguageSelector';
import GlassCard from './components/ui/GlassCard';
import StatusBadge from './components/ui/StatusBadge';
import TechButton from './components/ui/TechButton';
import { startScan, getScanStatus, getReport, getConfig, getHistoryDetail, getDefaultSubnet, getLogs } from './services/api';
import { LanguageProvider, useLanguage } from './LanguageContext';
import { ScanReport, ViewState, ScanOptions, FrontendConfig, UserMode } from './types';

const isValidIPv4Address = (address: string): boolean => {
  const parts = address.split('.');
  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const value = Number(part);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
};

const parseIPv6Section = (section: string, allowEmbeddedIPv4: boolean): { valid: boolean; count: number } => {
  if (!section) return { valid: true, count: 0 };

  const blocks = section.split(':');
  let count = 0;

  for (let index = 0; index < blocks.length; index += 1) {
    const block = blocks[index];
    if (!block) return { valid: false, count: 0 };

    const isLastBlock = index === blocks.length - 1;
    if (allowEmbeddedIPv4 && isLastBlock && block.includes('.')) {
      if (!isValidIPv4Address(block)) return { valid: false, count: 0 };
      count += 2;
      continue;
    }

    if (!/^[0-9A-Fa-f]{1,4}$/.test(block)) return { valid: false, count: 0 };
    count += 1;
  }

  return { valid: true, count };
};

const isValidIPv6Address = (address: string): boolean => {
  if (!address || address.includes(':::')) return false;

  const doubleColonParts = address.split('::');
  if (doubleColonParts.length > 2) return false;

  if (doubleColonParts.length === 1) {
    const parsed = parseIPv6Section(doubleColonParts[0], true);
    return parsed.valid && parsed.count === 8;
  }

  const [leftSection, rightSection] = doubleColonParts;
  if (leftSection.includes('.') && rightSection.length > 0) return false;

  const leftParsed = parseIPv6Section(leftSection, rightSection.length === 0);
  const rightParsed = parseIPv6Section(rightSection, true);

  if (!leftParsed.valid || !rightParsed.valid) return false;

  const totalBlocks = leftParsed.count + rightParsed.count;
  return totalBlocks < 8;
};

const isValidCidrSubnet = (value: string): boolean => {
  const trimmedValue = value.trim();
  const slashPosition = trimmedValue.lastIndexOf('/');

  if (slashPosition <= 0 || slashPosition === trimmedValue.length - 1) return false;

  const address = trimmedValue.slice(0, slashPosition);
  const prefixPart = trimmedValue.slice(slashPosition + 1);

  if (!/^\d+$/.test(prefixPart)) return false;

  const prefix = Number(prefixPart);

  if (isValidIPv4Address(address)) {
    return prefix >= 0 && prefix <= 32;
  }

  if (isValidIPv6Address(address)) {
    return prefix >= 0 && prefix <= 128;
  }

  return false;
};

const USER_MODE_STORAGE_KEY = 'cra-user-mode';
const THEME_STORAGE_KEY = 'cra-theme';

type ThemeMode = 'light' | 'dark';

const MODE_ACCENT: Record<UserMode, string> = {
  basic: 'var(--color-emerald)',
  intermediate: 'var(--color-cyan)',
  expert: 'var(--color-violet)'
};

const AppShell: React.FC = () => {
  const { t } = useLanguage();
  const [view, setView] = useState<ViewState>('dashboard');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [config, setConfig] = useState<FrontendConfig | null>(null);
  const [subnet, setSubnet] = useState('');
  const [isSubnetFocused, setIsSubnetFocused] = useState(false);
  const [userMode, setUserMode] = useState<UserMode>(() => {
    if (typeof window === 'undefined') return 'intermediate';
    const storedMode = window.localStorage.getItem(USER_MODE_STORAGE_KEY);
    if (storedMode === 'basic' || storedMode === 'intermediate' || storedMode === 'expert') {
      return storedMode;
    }
    return 'intermediate';
  });
  const [theme, setTheme] = useState<ThemeMode>(() => {
    if (typeof window === 'undefined') return 'dark';
    const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (storedTheme === 'light' || storedTheme === 'dark') {
      return storedTheme;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  });
  const [logs, setLogs] = useState<string[]>([]);
  const previousScanningRef = useRef(false);
  const recentScanCompletionRef = useRef<number | null>(null);

  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    scan_type: 'deep',
    auth_checks: true,
    vendors: 'all'
  });
  const [showSettings, setShowSettings] = useState(false);
  const [isModeMenuOpen, setIsModeMenuOpen] = useState(false);
  const [sidebarExpanded, setSidebarExpanded] = useState(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('cra-sidebar-expanded') === 'true';
  });

  const pollInterval = useRef<NodeJS.Timeout | null>(null);
  const viewRef = useRef(view);
  const modeMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    viewRef.current = view;
  }, [view]);

  const normalizedSubnet = subnet.trim();
  const isValidSubnet = isValidCidrSubnet(normalizedSubnet);
  const hasSubnetInput = normalizedSubnet.length > 0;
  const showSubnetHelper = isSubnetFocused || hasSubnetInput;
  const subnetLocked = userMode === 'basic';
  const canStartScan = !scanning && (userMode === 'basic' || isValidSubnet);
  const accentColor = MODE_ACCENT[userMode];
  const getModeLabel = (mode: UserMode): string => {
    if (mode === 'basic') return t('mode.basic');
    if (mode === 'intermediate') return t('mode.intermediate');
    return t('mode.expert');
  };

  const fetchData = useCallback(async () => {
    const statusData = await getScanStatus();

    if (statusData !== null) {
      const now = Date.now();
      if (previousScanningRef.current && !statusData.scanning) {
        recentScanCompletionRef.current = now;
      }
      previousScanningRef.current = statusData.scanning;

      setScanning(statusData.scanning);
      setLoading(false);

      if (statusData.error) {
        setScanError(statusData.error);
      }

      if (viewRef.current === 'dashboard' && !statusData.scanning) {
        const data = await getReport();
        if (data) setReport(data);
      }

      if (userMode === 'expert') {
        const logsData = await getLogs(180);
        if (logsData?.logs) {
          setLogs((previousLogs) => {
            const incomingLogs = logsData.logs;

            if (incomingLogs.length === 0 || previousLogs.length === 0) {
              return incomingLogs;
            }

            const scanJustCompleted = recentScanCompletionRef.current !== null
              && (now - recentScanCompletionRef.current) < 15000;

            const isUnexpectedCollapse = incomingLogs.length <= 2
              && previousLogs.length >= 10
              && scanJustCompleted;

            if (isUnexpectedCollapse) {
              return previousLogs;
            }

            return incomingLogs;
          });
        }
      }
    }
  }, [userMode]);

  useEffect(() => {
    getConfig().then(setConfig);
    fetchData();
    pollInterval.current = setInterval(fetchData, 3000);
    return () => {
      if (pollInterval.current) clearInterval(pollInterval.current);
    };
  }, [fetchData]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem('cra-sidebar-expanded', String(sidebarExpanded));
    }

    if (!sidebarExpanded) {
      setIsModeMenuOpen(false);
    }
  }, [sidebarExpanded]);

  useEffect(() => {
    if (!isModeMenuOpen) {
      return;
    }

    const handlePointerDown = (event: MouseEvent) => {
      if (!modeMenuRef.current?.contains(event.target as Node)) {
        setIsModeMenuOpen(false);
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsModeMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isModeMenuOpen]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(USER_MODE_STORAGE_KEY, userMode);
    }
  }, [userMode]);

  useEffect(() => {
    if (typeof document === 'undefined') {
      return;
    }

    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');

    if (typeof window !== 'undefined') {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    }
  }, [theme]);

  useEffect(() => {
    if (userMode !== 'basic') {
      return;
    }

    getDefaultSubnet().then((data) => {
      if (!data?.subnet) {
        return;
      }
      setSubnet(data.subnet);
    });

    setScanOptions((previous) => {
      const newScanType: ScanOptions['scan_type'] = previous.scan_type === 'deep' ? 'deep' : 'standard';

      return {
        ...previous,
        scan_type: newScanType,
        auth_checks: newScanType === 'deep',
        vendors: previous.vendors ?? 'all'
      };
    });
  }, [userMode]);

  useEffect(() => {
    if (userMode === 'basic' && view === 'devices') {
      setView('dashboard');
    }
  }, [userMode, view]);

  const handleScan = async () => {
    let targetSubnet = normalizedSubnet;

    if (userMode === 'basic' && !targetSubnet) {
      const enteredSubnet = window.prompt(t('prompt.autoSubnetFailed'), '192.168.1.0/24');
      if (!enteredSubnet) {
        setScanError(t('errors.subnetRequired'));
        return;
      }
      targetSubnet = enteredSubnet.trim();
      setSubnet(targetSubnet);
    }

    if (!isValidCidrSubnet(targetSubnet)) {
      setScanError(t('errors.invalidCidr'));
      return;
    }

    const effectiveOptions: ScanOptions = userMode === 'basic'
      ? (() => {
        const selectedDepth: ScanOptions['scan_type'] = scanOptions.scan_type === 'deep' ? 'deep' : 'standard';
        return {
          ...scanOptions,
          profile: selectedDepth,
          scan_type: selectedDepth,
          auth_checks: selectedDepth === 'deep',
          vendors: selectedDepth === 'deep' ? (scanOptions.vendors ?? 'all') : 'all'
        };
      })()
      : scanOptions;

    try {
      setScanning(true);
      previousScanningRef.current = true;
      recentScanCompletionRef.current = null;
      setScanError(null);
      setView('dashboard');
      await startScan(targetSubnet, effectiveOptions);
    } catch (e) {
      console.error(e);
      setScanning(false);
      alert(t('errors.startScanFailed'));
    }
  };

  const handleViewReport = async (id: number) => {
    const historicalReport = await getHistoryDetail(id);
    if (historicalReport) {
      setReport(historicalReport);
      setView('dashboard');
    } else {
      alert(t('errors.historyLoadFailed'));
    }
  };

  const handleModeChange = (mode: UserMode) => {
    setUserMode(mode);
    setIsModeMenuOpen(false);
    if (mode === 'basic' && view === 'devices') {
      setView('dashboard');
    }
  };

  const navItems: Array<{ id: ViewState; label: string; icon: React.ComponentType<{ size?: number }> }> = [
    { id: 'dashboard', label: t('nav.dashboard'), icon: LayoutDashboard },
    { id: 'history', label: t('nav.history'), icon: History }
  ];

  if (userMode !== 'basic') {
    navItems.splice(1, 0, { id: 'devices', label: t('nav.devices'), icon: List });
  }

  return (
    <div className="app-shell relative flex min-h-screen font-sans" style={{ '--color-accent': accentColor } as React.CSSProperties}>
      <aside className={`surface-panel fixed inset-y-0 left-0 z-30 border-r backdrop-blur-xl transition-all duration-300 ${sidebarExpanded ? 'w-64' : 'w-20'}`}>
        <div className={`flex h-full flex-col py-5 ${sidebarExpanded ? 'px-3' : 'items-center'}`}>
          <div className={`mb-6 flex items-center ${sidebarExpanded ? 'justify-between px-1' : 'flex-col gap-3'}`}>
            <div className="accent-ring flex h-11 w-11 items-center justify-center rounded-xl border shadow-[0_0_20px_color-mix(in_srgb,var(--color-accent)_28%,transparent)]">
              <ShieldCheck size={22} />
            </div>
            {sidebarExpanded && (
              <div className="mr-auto ml-3 min-w-0">
                <p className="text-main truncate text-sm font-semibold">CRA Auditor</p>
                <p className="text-soft text-[11px]">{t('app.commandUi')}</p>
              </div>
            )}
            <button
              onClick={() => setSidebarExpanded((prev) => !prev)}
              title={sidebarExpanded ? t('sidebar.collapse') : t('sidebar.expand')}
              className={`surface-card text-muted hover:text-main flex h-9 items-center rounded-lg border transition ${sidebarExpanded ? 'w-9 justify-center' : 'w-11 justify-center'}`}
            >
              {sidebarExpanded ? <ChevronsLeft size={16} /> : <ChevronsRight size={16} />}
            </button>
          </div>

          <nav className={`flex flex-1 flex-col gap-3 ${sidebarExpanded ? '' : 'items-center'}`}>
            {navItems.map(({ id, icon: Icon, label }) => (
              <button
                key={id}
                onClick={() => setView(id)}
                title={label}
                className={`group relative flex h-11 items-center rounded-xl border transition-all ${sidebarExpanded ? 'w-full justify-start gap-3 px-3' : 'w-11 justify-center'} ${view === id
                  ? 'accent-ring shadow-[0_0_18px_color-mix(in_srgb,var(--color-accent)_22%,transparent)]'
                  : 'surface-card text-muted hover:text-main'
                  }`}
              >
                <Icon size={18} />
                {sidebarExpanded ? (
                  <span className="text-sm font-medium">{label}</span>
                ) : (
                  <span className="surface-elevated text-main pointer-events-none absolute left-14 hidden rounded-md border px-2 py-1 text-xs group-hover:block">
                    {label}
                  </span>
                )}
              </button>
            ))}

            {sidebarExpanded && (
              <div className="surface-card mt-2 rounded-xl border p-3">
                <label className="text-soft mb-2 block text-[11px] font-semibold uppercase tracking-widest">{t('sidebar.uiMode')}</label>
                <div ref={modeMenuRef} className="relative">
                  <button
                    type="button"
                    disabled={scanning}
                    aria-haspopup="listbox"
                    aria-expanded={isModeMenuOpen}
                    onClick={() => setIsModeMenuOpen((prev) => !prev)}
                    className="surface-elevated text-main flex w-full items-center justify-between rounded-xl border px-2 py-2 text-sm outline-none transition focus:border-[var(--color-accent-border)] disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <span>{getModeLabel(userMode)}</span>
                    <span className="text-soft text-xs">▾</span>
                  </button>
                  {isModeMenuOpen && (
                    <div className="surface-elevated absolute z-20 mt-2 w-full overflow-hidden rounded-xl border" role="listbox" aria-label={t('sidebar.uiModeOptions')}>
                      {(['basic', 'intermediate', 'expert'] as UserMode[]).map((modeOption) => (
                        <button
                          key={modeOption}
                          type="button"
                          role="option"
                          aria-selected={userMode === modeOption}
                          onClick={() => handleModeChange(modeOption)}
                          className={`text-main hover:bg-[var(--panel-hover)] w-full px-3 py-2 text-left text-sm transition ${userMode === modeOption ? 'bg-[var(--panel-selected)] font-semibold' : ''}`}
                        >
                          {getModeLabel(modeOption)}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <p className="text-soft mt-2 text-xs">{t('sidebar.uiModeHint')}</p>
              </div>
            )}
          </nav>

          <div className={`mt-auto ${sidebarExpanded ? '' : 'w-full px-1'}`}>
            {sidebarExpanded && <LanguageSelector />}
            <button
              onClick={() => setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))}
              title={theme === 'dark' ? t('sidebar.theme.toLight') : t('sidebar.theme.toDark')}
              className={`surface-card text-muted hover:text-main flex h-11 items-center rounded-xl border transition ${sidebarExpanded ? 'w-full justify-start gap-3 px-3' : 'mx-auto w-11 justify-center'}`}
            >
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
              {sidebarExpanded && <span className="text-sm font-medium">{theme === 'dark' ? t('sidebar.theme.light') : t('sidebar.theme.dark')}</span>}
            </button>
          </div>
        </div>
      </aside>

      <main className={`flex-1 p-5 transition-all duration-300 md:p-7 ${sidebarExpanded ? 'ml-64' : 'ml-20'}`}>
        <div className="space-y-6">
          <GlassCard className="sticky top-5 z-20 rounded-2xl border border-[var(--color-accent-border)] px-5 py-4 md:px-6">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div className="flex min-w-0 items-center gap-3 md:gap-4">
                <div>
                  <h1 className="text-main text-lg font-bold tracking-tight md:text-xl">{t('header.title')}</h1>
                  <p className="text-muted text-sm">{t('header.subtitle')}</p>
                </div>
                <StatusBadge label={scanning ? t('status.scanActive') : t('status.idle')} tone={scanning ? 'info' : 'success'} pulse={scanning} />
                <StatusBadge label={`${t('status.mode')} ${getModeLabel(userMode)}`} tone="neutral" />
              </div>

              <div className="flex flex-col gap-2 md:items-end">
                <div className="flex flex-col gap-3 md:flex-row md:items-center">
                  {subnetLocked ? (
                    <div className="surface-elevated text-main min-w-[260px] rounded-xl border px-3 py-2 text-sm">
                      {t('subnet.auto')}: {subnet || t('subnet.detecting')}
                    </div>
                  ) : (
                    <div className={`surface-elevated flex min-w-[260px] items-center rounded-xl border px-3 py-2 transition ${hasSubnetInput ? (isValidSubnet ? 'border-emerald-500/50' : 'border-rose-500/55') : (isSubnetFocused ? 'border-[var(--color-accent-border)]' : '')}`}>
                      <input
                        type="text"
                        value={subnet}
                        onChange={(e) => setSubnet(e.target.value)}
                        onFocus={() => setIsSubnetFocused(true)}
                        onBlur={() => setIsSubnetFocused(false)}
                        className="text-main w-full bg-transparent text-sm outline-none placeholder:text-[var(--text-soft)]"
                        placeholder={t('subnet.placeholder')}
                      />
                    </div>
                  )}
                  <TechButton onClick={() => setShowSettings(true)} disabled={scanning} variant="secondary">
                    <Settings size={15} />
                    {t('actions.settings')}
                  </TechButton>
                  <TechButton onClick={handleScan} disabled={!canStartScan} variant="primary" className="neon-text">
                    {scanning ? <RotateCw className="animate-spin" size={15} /> : <Play size={15} />}
                    {scanning ? t('actions.scanning') : t('actions.startScan')}
                  </TechButton>
                </div>

                {!subnetLocked && showSubnetHelper && (
                  <div className={`w-full rounded-lg border px-3 py-2 text-xs md:max-w-[540px] ${hasSubnetInput ? (isValidSubnet ? 'text-[var(--badge-success-text)] border-[var(--badge-success-border)] bg-[var(--badge-success-bg)]' : 'text-[var(--badge-danger-text)] border-[var(--badge-danger-border)] bg-[var(--badge-danger-bg)]') : 'surface-card text-muted'}`}>
                    {!hasSubnetInput && (
                      <p>{t('subnet.helper.empty')}</p>
                    )}
                    {hasSubnetInput && isValidSubnet && (
                      <p>{t('subnet.helper.valid')}</p>
                    )}
                    {hasSubnetInput && !isValidSubnet && (
                      <p>{t('subnet.helper.invalid')}</p>
                    )}
                  </div>
                )}
              </div>
            </div>

            {report && view !== 'history' && (
              <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-[var(--border-subtle)] pt-3">
                <StatusBadge label={`${t('status.lastScan')} ${new Date(report.timestamp).toLocaleTimeString()}`} tone="neutral" />
                {report.scanProfile && <StatusBadge label={`${t('status.profile')} ${report.scanProfile}`} tone="info" />}
                <StatusBadge label={config?.gemini_enabled ? t('status.geminiOnline') : t('status.geminiDisabled')} tone="neutral" />
                <StatusBadge label={config?.nvd_enabled ? t('status.nvdOnline') : t('status.nvdDisabled')} tone="neutral" />
              </div>
            )}
          </GlassCard>

          {scanError && !scanning && (
            <GlassCard className="rounded-2xl p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle size={20} className="mt-0.5 shrink-0 text-[var(--badge-danger-text)]" />
                <div>
                  <h4 className="text-base font-semibold text-[var(--badge-danger-text)]">{t('errors.scanFailed')}</h4>
                  <p className="text-muted text-sm">{scanError}</p>
                </div>
                <button onClick={() => setScanError(null)} className="text-muted hover:text-main ml-auto">
                  <X size={16} />
                </button>
              </div>
            </GlassCard>
          )}

          <div>
            {loading ? (
              <GlassCard className="rounded-2xl p-10">
                <div className="flex h-[50vh] flex-col items-center justify-center gap-4">
                  <RotateCw className="accent-text animate-spin" size={40} />
                  <p className="text-muted">{t('loading.commandChannel')}</p>
                </div>
              </GlassCard>
            ) : (
              <div className={`relative ${scanning && !report && view !== 'history' ? 'min-h-[360px]' : ''}`}>
                {view === 'dashboard' && report && userMode === 'basic' && <BasicDashboard report={report} />}
                {view === 'dashboard' && report && userMode === 'intermediate' && <IntermediateDashboard report={report} config={config} />}
                {view === 'dashboard' && report && userMode === 'expert' && <ExpertDashboard report={report} config={config} logs={logs} />}
                {view === 'devices' && report && <DeviceList devices={report.devices} />}
                {view === 'history' && <HistoryView onViewReport={handleViewReport} />}

                {!report && view !== 'history' && !scanning && (
                  <GlassCard className="rounded-2xl p-10">
                    <div className="py-14 text-center">
                      <div className="accent-ring mx-auto mb-5 inline-flex h-14 w-14 items-center justify-center rounded-full border">
                        <ShieldCheck size={28} />
                      </div>
                      <h3 className="text-main text-xl font-bold">{t('empty.readyTitle')}</h3>
                      <p className="text-soft mx-auto mt-2 max-w-md text-sm">
                        {t('empty.readyDescription')}
                      </p>
                    </div>
                  </GlassCard>
                )}

                {scanning && (
                  <div className="scan-overlay absolute inset-0 z-20 rounded-2xl border p-6 backdrop-blur-sm">
                    <div className="scan-grid absolute inset-0 rounded-2xl opacity-40" />
                    <div className="terminal-panel relative h-full overflow-hidden rounded-xl border p-4 font-mono text-sm text-[var(--color-accent)]">
                      <div className="mb-3 flex items-center gap-2 border-b border-[var(--border-subtle)] pb-2">
                        <Activity size={15} className="accent-text" />
                        <span className="accent-text uppercase tracking-widest">{t('overlay.commandTerminal')}</span>
                      </div>
                      <div className="space-y-2 text-[color-mix(in_srgb,var(--color-accent)_86%,var(--text-main))]">
                        {userMode === 'basic' ? (
                          <>
                            <p>{t('overlay.basic.line1')}</p>
                            <p>{t('overlay.basic.line2')}</p>
                            <p className="typing-cursor">{t('overlay.basic.line3')}</p>
                          </>
                        ) : (
                          <>
                            <p>&gt; initialize_probe --target {subnet || 'pending_target'} --profile {scanOptions.scan_type}</p>
                            <p>&gt; network_discovery --passive</p>
                            <p>&gt; service_fingerprint --mode aggressive</p>
                            <p>&gt; cve_correlation --source nvd</p>
                            <p className="typing-cursor">&gt; compliance_ruleset --annex-i --streaming</p>
                          </>
                        )}
                      </div>
                      <div className="text-muted mt-4 flex items-center gap-3 text-xs uppercase tracking-widest">
                        <span className="inline-flex items-center gap-1"><span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />{t('overlay.scannerActive')}</span>
                        <span className="inline-flex items-center gap-1"><span className="h-2 w-2 animate-pulse rounded-full bg-[var(--color-accent)]" />{t('overlay.streamingLogs')}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>

      <SettingsModal
        show={showSettings}
        scanning={scanning}
        mode={userMode}
        scanOptions={scanOptions}
        onClose={() => setShowSettings(false)}
        onScanOptionsChange={setScanOptions}
      />
    </div>
  );
};

const App: React.FC = () => (
  <LanguageProvider>
    <AppShell />
  </LanguageProvider>
);

export default App;
