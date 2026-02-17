import { Activity, AlertTriangle, ChevronsLeft, ChevronsRight, History, LayoutDashboard, List, Play, RotateCw, Settings, ShieldCheck, X, CheckSquare, Square } from 'lucide-react';
import React, { useEffect, useState, useRef, useCallback } from 'react';
import Dashboard from './components/Dashboard';
import DeviceList from './components/DeviceList';
import HistoryView from './components/HistoryView';
import GlassCard from './components/ui/GlassCard';
import StatusBadge from './components/ui/StatusBadge';
import TechButton from './components/ui/TechButton';
import { startScan, getScanStatus, getReport, getConfig, getHistoryDetail } from './services/api';
import { ScanReport, ViewState, ScanOptions, FrontendConfig } from './types';

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

const App: React.FC = () => {
  const [view, setView] = useState<ViewState>('dashboard');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [config, setConfig] = useState<FrontendConfig | null>(null);
  const [subnet, setSubnet] = useState('');
  const [isSubnetFocused, setIsSubnetFocused] = useState(false);

  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    scan_type: 'deep',
    auth_checks: true,
    vendors: 'all'
  });
  const [showSettings, setShowSettings] = useState(false);
  const [sidebarExpanded, setSidebarExpanded] = useState(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('cra-sidebar-expanded') === 'true';
  });

  const pollInterval = useRef<NodeJS.Timeout | null>(null);
  const viewRef = useRef(view);

  useEffect(() => {
    viewRef.current = view;
  }, [view]);

  const normalizedSubnet = subnet.trim();
  const isValidSubnet = isValidCidrSubnet(normalizedSubnet);
  const hasSubnetInput = normalizedSubnet.length > 0;
  const showSubnetHelper = isSubnetFocused || hasSubnetInput;

  const fetchData = useCallback(async () => {
    const statusData = await getScanStatus();

    if (statusData !== null) {
      setScanning(statusData.scanning);
      setLoading(false);

      if (statusData.error) {
        setScanError(statusData.error);
      }

      if (viewRef.current === 'dashboard' && !statusData.scanning) {
        const data = await getReport();
        if (data) setReport(data);
      }
    }
  }, []);

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
  }, [sidebarExpanded]);

  const handleScan = async () => {
    if (!isValidSubnet) {
      setScanError('Invalid CIDR format. Use IPv4 (e.g. 192.168.1.0/24) or IPv6 (e.g. 2001:db8::/64).');
      return;
    }

    try {
      setScanning(true);
      setScanError(null);
      setView('dashboard');
      await startScan(normalizedSubnet, scanOptions);
    } catch (e) {
      console.error(e);
      setScanning(false);
      alert('Failed to start scan. Check console.');
    }
  };

  const handleViewReport = async (id: number) => {
    const historicalReport = await getHistoryDetail(id);
    if (historicalReport) {
      setReport(historicalReport);
      setView('dashboard');
    } else {
      alert('Failed to load historical report.');
    }
  };

  const navItems: Array<{ id: ViewState; label: string; icon: React.ComponentType<{ size?: number }> }> = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'devices', label: 'Devices', icon: List },
    { id: 'history', label: 'History', icon: History }
  ];

  return (
    <div className="relative flex min-h-screen bg-transparent font-sans text-slate-200">
      <aside className={`fixed inset-y-0 left-0 z-30 border-r border-slate-800/80 bg-slate-950/70 backdrop-blur-xl transition-all duration-300 ${sidebarExpanded ? 'w-64' : 'w-20'}`}>
        <div className={`flex h-full flex-col py-5 ${sidebarExpanded ? 'px-3' : 'items-center'}`}>
          <div className={`mb-6 flex items-center ${sidebarExpanded ? 'justify-between px-1' : 'flex-col gap-3'}`}>
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-400/30 bg-emerald-500/10 text-emerald-300 shadow-[0_0_20px_rgba(52,211,153,0.2)]">
              <ShieldCheck size={22} />
            </div>
            {sidebarExpanded && (
              <div className="mr-auto ml-3 min-w-0">
                <p className="truncate text-sm font-semibold text-white">CRA Auditor</p>
                <p className="text-[11px] text-slate-400">Command UI</p>
              </div>
            )}
            <button
              onClick={() => setSidebarExpanded((prev) => !prev)}
              title={sidebarExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
              className={`flex h-9 items-center rounded-lg border border-slate-700/70 bg-slate-900/60 text-slate-300 transition hover:border-slate-500 hover:text-white ${sidebarExpanded ? 'w-9 justify-center' : 'w-11 justify-center'}`}
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
                  ? 'border-cyan-400/40 bg-cyan-500/15 text-cyan-200 shadow-[0_0_18px_rgba(34,211,238,0.18)]'
                  : 'border-slate-700/70 bg-slate-900/60 text-slate-400 hover:border-slate-500 hover:text-white'
                  }`}
              >
                <Icon size={18} />
                {sidebarExpanded ? (
                  <span className="text-sm font-medium">{label}</span>
                ) : (
                  <span className="pointer-events-none absolute left-14 hidden rounded-md border border-slate-600/60 bg-slate-900/95 px-2 py-1 text-xs text-slate-200 group-hover:block">
                    {label}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>
      </aside>

      <main className={`flex-1 p-5 transition-all duration-300 md:p-7 ${sidebarExpanded ? 'ml-64' : 'ml-20'}`}>
        <div className="space-y-6">
          <GlassCard className="sticky top-5 z-20 rounded-2xl px-5 py-4 md:px-6">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div className="flex min-w-0 items-center gap-3 md:gap-4">
                <div>
                  <h1 className="text-lg font-bold tracking-tight text-white md:text-xl">CRA Auditor Command</h1>
                  <p className="text-sm text-slate-300">Live compliance intelligence for Home Assistant environments</p>
                </div>
                <StatusBadge label={scanning ? 'Scan Active' : 'Idle'} tone={scanning ? 'info' : 'success'} pulse={scanning} />
              </div>

              <div className="flex flex-col gap-2 md:items-end">
                <div className="flex flex-col gap-3 md:flex-row md:items-center">
                  <div className={`flex min-w-[260px] items-center rounded-xl border bg-slate-900/70 px-3 py-2 transition ${hasSubnetInput ? (isValidSubnet ? 'border-emerald-400/50' : 'border-rose-400/50') : (isSubnetFocused ? 'border-cyan-400/50' : 'border-slate-700/80')}`}>
                  <input
                    type="text"
                    value={subnet}
                    onChange={(e) => setSubnet(e.target.value)}
                    onFocus={() => setIsSubnetFocused(true)}
                    onBlur={() => setIsSubnetFocused(false)}
                    className="w-full bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500"
                    placeholder="Target CIDR (e.g. 192.168.1.0/24 or 2001:db8::/64)"
                  />
                </div>
                <TechButton onClick={() => setShowSettings(true)} disabled={scanning} variant="secondary">
                  <Settings size={15} />
                  Settings
                </TechButton>
                <TechButton onClick={handleScan} disabled={scanning || !isValidSubnet} variant="primary" className="neon-text">
                  {scanning ? <RotateCw className="animate-spin" size={15} /> : <Play size={15} />}
                  {scanning ? 'Scanning' : 'Start Scan'}
                </TechButton>
                </div>

                {showSubnetHelper && (
                  <div className={`w-full rounded-lg border px-3 py-2 text-xs md:max-w-[540px] ${hasSubnetInput ? (isValidSubnet ? 'border-emerald-400/30 bg-emerald-500/10 text-emerald-200' : 'border-rose-400/30 bg-rose-500/10 text-rose-200') : 'border-slate-700/70 bg-slate-900/60 text-slate-300'}`}>
                    {!hasSubnetInput && (
                      <p>CIDR only. Enter a subnet, not a single host IP.</p>
                    )}
                    {hasSubnetInput && isValidSubnet && (
                      <p>Valid subnet target. Ready to start scan.</p>
                    )}
                    {hasSubnetInput && !isValidSubnet && (
                      <p>Invalid CIDR. Use IPv4 like 192.168.1.0/24 or IPv6 like 2001:db8::/64.</p>
                    )}
                  </div>
                )}
              </div>
            </div>

            {report && view !== 'history' && (
              <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-700/70 pt-3">
                <StatusBadge label={`Last Scan ${new Date(report.timestamp).toLocaleTimeString()}`} tone="neutral" />
                {report.scanProfile && <StatusBadge label={`Profile ${report.scanProfile}`} tone="info" />}
                <StatusBadge label={config?.gemini_enabled ? 'Gemini Online' : 'Gemini Disabled'} tone={config?.gemini_enabled ? 'success' : 'warning'} />
                <StatusBadge label={config?.nvd_enabled ? 'NVD Online' : 'NVD Disabled'} tone={config?.nvd_enabled ? 'success' : 'danger'} />
              </div>
            )}
          </GlassCard>

          {scanError && !scanning && (
            <GlassCard className="rounded-2xl p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle size={20} className="mt-0.5 shrink-0 text-rose-300" />
                <div>
                  <h4 className="text-base font-semibold text-rose-200">Scan Failed</h4>
                  <p className="text-sm text-slate-300">{scanError}</p>
                </div>
                <button onClick={() => setScanError(null)} className="ml-auto text-slate-400 hover:text-white">
                  <X size={16} />
                </button>
              </div>
            </GlassCard>
          )}

          <div>
            {loading ? (
              <GlassCard className="rounded-2xl p-10">
                <div className="flex h-[50vh] flex-col items-center justify-center gap-4">
                  <RotateCw className="animate-spin text-cyan-300" size={40} />
                  <p className="text-slate-300">Establishing command channel...</p>
                </div>
              </GlassCard>
            ) : (
              <div className={`relative ${scanning && !report && view !== 'history' ? 'min-h-[360px]' : ''}`}>
                {view === 'dashboard' && report && <Dashboard report={report} geminiEnabled={config?.gemini_enabled} nvdEnabled={config?.nvd_enabled} />}
                {view === 'devices' && report && <DeviceList devices={report.devices} />}
                {view === 'history' && <HistoryView onViewReport={handleViewReport} />}

                {!report && view !== 'history' && !scanning && (
                  <GlassCard className="rounded-2xl p-10">
                    <div className="py-14 text-center">
                      <div className="mx-auto mb-5 inline-flex h-14 w-14 items-center justify-center rounded-full border border-cyan-400/30 bg-cyan-500/10 text-cyan-200">
                        <ShieldCheck size={28} />
                      </div>
                      <h3 className="text-xl font-bold text-white">Ready for Network Audit</h3>
                      <p className="mx-auto mt-2 max-w-md text-sm text-slate-400">
                        Enter a target subnet in the command bar and launch a scan to generate your CRA compliance report.
                      </p>
                    </div>
                  </GlassCard>
                )}

                {scanning && (
                  <div className="absolute inset-0 z-20 rounded-2xl border border-cyan-500/20 bg-slate-950/75 p-6 backdrop-blur-sm">
                    <div className="scan-grid absolute inset-0 rounded-2xl opacity-40" />
                    <div className="relative h-full overflow-hidden rounded-xl border border-cyan-400/25 bg-slate-950/90 p-4 font-mono text-sm text-cyan-200">
                      <div className="mb-3 flex items-center gap-2 border-b border-slate-700/70 pb-2">
                        <Activity size={15} className="text-cyan-300" />
                        <span className="uppercase tracking-widest text-cyan-200">Command Terminal</span>
                      </div>
                      <div className="space-y-2 text-cyan-100/90">
                        <p>&gt; initialize_probe --target {subnet || 'pending_target'} --profile {scanOptions.scan_type}</p>
                        <p>&gt; network_discovery --passive</p>
                        <p>&gt; service_fingerprint --mode aggressive</p>
                        <p>&gt; cve_correlation --source nvd</p>
                        <p className="typing-cursor">&gt; compliance_ruleset --annex-i --streaming</p>
                      </div>
                      <div className="mt-4 flex items-center gap-3 text-xs uppercase tracking-widest text-slate-200">
                        <span className="inline-flex items-center gap-1"><span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />Scanner Active</span>
                        <span className="inline-flex items-center gap-1"><span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400" />Streaming logs</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>

      {showSettings && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-2xl overflow-hidden rounded-2xl border border-slate-700/80 bg-slate-900/95 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-700/70 bg-slate-800/60 p-4">
              <h3 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-cyan-200">
                <Settings size={16} /> Scan Configuration
              </h3>
              <button onClick={() => setShowSettings(false)} className="text-slate-400 transition hover:text-white">
                <X size={18} />
              </button>
            </div>

            <div className="space-y-5 p-6">
              <div>
                <label className="mb-2 block text-sm font-semibold uppercase tracking-wider text-slate-300">Scan Depth</label>
                <div className="grid grid-cols-3 gap-2">
                  {(['discovery', 'standard', 'deep'] as const).map((type) => (
                    <button
                      key={type}
                      onClick={() => setScanOptions({ ...scanOptions, scan_type: type })}
                      className={`rounded-lg border px-3 py-2 text-sm font-semibold capitalize transition ${scanOptions.scan_type === type
                        ? 'border-cyan-400/50 bg-cyan-500/20 text-cyan-200'
                        : 'border-slate-700 bg-slate-800/70 text-slate-300 hover:text-white'
                        }`}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>

              <div className={scanOptions.scan_type === 'discovery' ? 'pointer-events-none opacity-50' : ''}>
                <label className="mb-2 block text-sm font-semibold uppercase tracking-wider text-slate-300">Vendor Detection</label>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => setScanOptions({ ...scanOptions, vendors: 'all' })}
                    className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-semibold transition ${scanOptions.vendors === 'all'
                      ? 'border-emerald-400/40 bg-emerald-500/20 text-emerald-200'
                      : 'border-slate-700 bg-slate-800/70 text-slate-300'
                      }`}
                  >
                    {scanOptions.vendors === 'all' ? <CheckSquare size={12} /> : <Square size={12} />}
                    All Vendors
                  </button>
                  <button
                    onClick={() => setScanOptions({ ...scanOptions, vendors: [] })}
                    className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-semibold transition ${Array.isArray(scanOptions.vendors) && scanOptions.vendors.length === 0
                      ? 'border-emerald-400/40 bg-emerald-500/20 text-emerald-200'
                      : 'border-slate-700 bg-slate-800/70 text-slate-300'
                      }`}
                  >
                    {Array.isArray(scanOptions.vendors) && scanOptions.vendors.length === 0 ? <CheckSquare size={12} /> : <Square size={12} />}
                    No Vendors
                  </button>
                  {['tuya', 'shelly', 'hue', 'kasa', 'sonoff', 'ikea'].map((vendor) => {
                    const isSelected = scanOptions.vendors === 'all' || (Array.isArray(scanOptions.vendors) && scanOptions.vendors.includes(vendor));
                    return (
                      <button
                        key={vendor}
                        onClick={() => {
                          let current = scanOptions.vendors;
                          if (current === 'all') {
                            current = [vendor];
                          } else {
                            if (current.includes(vendor)) {
                              current = current.filter(v => v !== vendor);
                              if (current.length === 0) current = [];
                            } else {
                              current = [...current, vendor];
                            }
                          }
                          setScanOptions({ ...scanOptions, vendors: current });
                        }}
                        className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-semibold capitalize transition ${isSelected
                          ? 'border-violet-400/40 bg-violet-500/20 text-violet-200'
                          : 'border-slate-700 bg-slate-800/70 text-slate-300'
                          }`}
                      >
                        {isSelected ? <CheckSquare size={12} /> : <Square size={12} />}
                        {vendor}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className={scanOptions.scan_type === 'discovery' ? 'pointer-events-none opacity-50' : ''}>
                <label className="flex items-start gap-3 rounded-xl border border-slate-700 bg-slate-800/70 p-3">
                  <input
                    type="checkbox"
                    checked={Boolean(scanOptions.auth_checks)}
                    onChange={() => setScanOptions({ ...scanOptions, auth_checks: !scanOptions.auth_checks })}
                    className="mt-0.5"
                  />
                  <div>
                    <div className="text-sm font-medium text-slate-100">Active Vulnerability Probing</div>
                    <div className="text-sm text-slate-300">Attempt safe default credential logins and unauth API checks.</div>
                  </div>
                </label>
              </div>
            </div>

            <div className="flex justify-end border-t border-slate-700/70 bg-slate-800/60 p-4">
              <TechButton onClick={() => setShowSettings(false)} variant="primary">Save & Close</TechButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
