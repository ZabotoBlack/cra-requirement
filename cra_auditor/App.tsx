import { Activity, AlertTriangle, History, LayoutDashboard, List, Play, RotateCw, Settings, ShieldCheck, X, CheckSquare, Square } from 'lucide-react';
import React, { useEffect, useState, useRef, useCallback } from 'react';
import Dashboard from './components/Dashboard';
import DeviceList from './components/DeviceList';
import HistoryView from './components/HistoryView';
import GlassCard from './components/ui/GlassCard';
import StatusBadge from './components/ui/StatusBadge';
import TechButton from './components/ui/TechButton';
import { startScan, getScanStatus, getReport, getConfig, getHistoryDetail } from './services/api';
import { ScanReport, ViewState, ScanOptions, FrontendConfig } from './types';

const App: React.FC = () => {
  const [view, setView] = useState<ViewState>('dashboard');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [config, setConfig] = useState<FrontendConfig | null>(null);
  const [subnet, setSubnet] = useState('');

  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    scan_type: 'deep',
    auth_checks: true,
    vendors: 'all'
  });
  const [showSettings, setShowSettings] = useState(false);

  const pollInterval = useRef<NodeJS.Timeout | null>(null);
  const viewRef = useRef(view);

  useEffect(() => {
    viewRef.current = view;
  }, [view]);

  const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])$/;
  const isValidSubnet = cidrRegex.test(subnet);

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

  const handleScan = async () => {
    try {
      setScanning(true);
      setScanError(null);
      setView('dashboard');
      await startScan(subnet, scanOptions);
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
      <aside className="fixed inset-y-0 left-0 z-30 w-20 border-r border-slate-800/80 bg-slate-950/70 backdrop-blur-xl">
        <div className="flex h-full flex-col items-center py-5">
          <div className="mb-8 flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-400/30 bg-emerald-500/10 text-emerald-300 shadow-[0_0_20px_rgba(52,211,153,0.2)]">
            <ShieldCheck size={22} />
          </div>

          <nav className="flex flex-1 flex-col items-center gap-3">
            {navItems.map(({ id, icon: Icon, label }) => (
              <button
                key={id}
                onClick={() => setView(id)}
                title={label}
                className={`group relative flex h-11 w-11 items-center justify-center rounded-xl border transition-all ${view === id
                  ? 'border-cyan-400/40 bg-cyan-500/15 text-cyan-200 shadow-[0_0_18px_rgba(34,211,238,0.18)]'
                  : 'border-slate-700/70 bg-slate-900/60 text-slate-400 hover:border-slate-500 hover:text-white'
                  }`}
              >
                <Icon size={18} />
                <span className="pointer-events-none absolute left-14 hidden rounded-md border border-slate-600/60 bg-slate-900/95 px-2 py-1 text-xs text-slate-200 group-hover:block">
                  {label}
                </span>
              </button>
            ))}
          </nav>

          <button
            onClick={() => setShowSettings(true)}
            title="Scan Settings"
            className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-700/70 bg-slate-900/60 text-slate-300 transition hover:border-slate-500 hover:text-white"
          >
            <Settings size={18} />
          </button>
        </div>
      </aside>

      <main className="ml-20 flex-1 p-5 md:p-7">
        <div className="space-y-6">
          <GlassCard className="sticky top-5 z-20 rounded-2xl px-4 py-3 md:px-6">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div className="flex min-w-0 items-center gap-3 md:gap-4">
                <div>
                  <h1 className="text-lg font-bold tracking-tight text-white md:text-xl">CRA Auditor Command</h1>
                  <p className="text-xs text-slate-400">Live compliance intelligence for Home Assistant environments</p>
                </div>
                <StatusBadge label={scanning ? 'Scan Active' : 'Idle'} tone={scanning ? 'info' : 'success'} pulse={scanning} />
              </div>

              <div className="flex flex-col gap-3 md:flex-row md:items-center">
                <div className="flex min-w-[260px] items-center rounded-xl border border-slate-700/80 bg-slate-900/70 px-3 py-2">
                  <input
                    type="text"
                    value={subnet}
                    onChange={(e) => setSubnet(e.target.value)}
                    className="w-full bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500"
                    placeholder="Target CIDR (e.g. 192.168.1.0/24)"
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
            </div>

            {!isValidSubnet && subnet.length > 0 && (
              <p className="mt-2 text-xs text-rose-300">Invalid CIDR format (example: 192.168.1.0/24).</p>
            )}

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
                  <h4 className="text-sm font-semibold text-rose-200">Scan Failed</h4>
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
              <div className="relative">
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
                    <div className="relative h-full overflow-hidden rounded-xl border border-cyan-400/25 bg-slate-950/90 p-4 font-mono text-xs text-cyan-200 md:text-sm">
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
                      <div className="mt-4 flex items-center gap-3 text-[11px] uppercase tracking-widest text-slate-300">
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

            <div className="space-y-5 p-5">
              <div>
                <label className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400">Scan Depth</label>
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
                <label className="mb-2 block text-xs font-semibold uppercase tracking-wider text-slate-400">Vendor Detection</label>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => setScanOptions({ ...scanOptions, vendors: 'all' })}
                    className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold transition ${scanOptions.vendors === 'all'
                      ? 'border-emerald-400/40 bg-emerald-500/20 text-emerald-200'
                      : 'border-slate-700 bg-slate-800/70 text-slate-300'
                      }`}
                  >
                    {scanOptions.vendors === 'all' ? <CheckSquare size={12} /> : <Square size={12} />}
                    All Vendors
                  </button>
                  <button
                    onClick={() => setScanOptions({ ...scanOptions, vendors: [] })}
                    className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold transition ${Array.isArray(scanOptions.vendors) && scanOptions.vendors.length === 0
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
                              if (current.length === 0) current = 'all';
                            } else {
                              current = [...current, vendor];
                            }
                          }
                          setScanOptions({ ...scanOptions, vendors: current });
                        }}
                        className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold capitalize transition ${isSelected
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
                    <div className="text-xs text-slate-400">Attempt safe default credential logins and unauth API checks.</div>
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
