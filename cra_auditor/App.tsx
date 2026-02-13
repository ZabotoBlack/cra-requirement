import { Activity, AlertTriangle, LayoutDashboard, List, Play, RotateCw, ShieldCheck, History, Settings, X, CheckSquare, Square } from 'lucide-react';
import React, { useEffect, useState, useRef, useCallback } from 'react';
import Dashboard from './components/Dashboard';
import DeviceList from './components/DeviceList';
import HistoryView from './components/HistoryView';
import { startScan, getScanStatus, getReport, getConfig, getHistoryDetail } from './services/api';
import { ScanReport, ViewState, ScanOptions } from './types';

const App: React.FC = () => {
  const [view, setView] = useState<ViewState>('dashboard');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [config, setConfig] = useState<{ gemini_enabled: boolean; version: string } | null>(null);
  const [subnet, setSubnet] = useState('');

  const [scanOptions, setScanOptions] = useState<ScanOptions>({
    scan_type: 'deep',
    auth_checks: true,
    vendors: 'all'
  });
  const [showSettings, setShowSettings] = useState(false);

  const pollInterval = useRef<NodeJS.Timeout | null>(null);
  const viewRef = useRef(view);
  const scanningRef = useRef(scanning);

  // Keep refs in sync with state
  useEffect(() => { viewRef.current = view; }, [view]);
  useEffect(() => { scanningRef.current = scanning; }, [scanning]);

  // CIDR Regex Validation
  const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])$/;
  const isValidSubnet = cidrRegex.test(subnet);

  const fetchData = useCallback(async () => {
    const statusData = await getScanStatus();

    // Only update scanning state on successful fetch; preserve last known state on error
    if (statusData !== null) {
      setScanning(statusData.scanning);
      setLoading(false);

      if (statusData.error) {
        setScanError(statusData.error);
      }

      // Auto-refresh report when not scanning and on dashboard view
      if (viewRef.current === 'dashboard' && !statusData.scanning) {
        const data = await getReport();
        if (data) setReport(data);
      }
    }
  }, []);

  // Initial load and polling setup
  useEffect(() => {
    getConfig().then(setConfig);
    fetchData();
    pollInterval.current = setInterval(fetchData, 3000); // Poll every 3 seconds
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
      // Polling will pick up the status change
    } catch (e) {
      console.error(e);
      setScanning(false);
      alert("Failed to start scan. Check console.");
    }
  };

  const handleViewReport = async (id: number) => {
    const historicalReport = await getHistoryDetail(id);
    if (historicalReport) {
      setReport(historicalReport);
      setView('dashboard');
    } else {
      alert("Failed to load historical report.");
    }
  };

  const NavItem = ({ id, label, icon: Icon }: { id: ViewState, label: string, icon: any }) => (
    <button
      onClick={() => setView(id)}
      className={`flex items-center gap-3 px-4 py-3 w-full rounded-lg transition-all ${view === id
        ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-900/20'
        : 'text-slate-400 hover:bg-slate-800 hover:text-white'
        }`}
    >
      <Icon size={20} />
      <span className="font-medium">{label}</span>
    </button>
  );

  return (
    <div className="flex min-h-screen bg-slate-950 font-sans text-slate-200">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800 bg-slate-900/50 flex flex-col fixed h-full z-10">
        <div className="p-6 border-b border-slate-800 flex items-center gap-2">
          <ShieldCheck className="text-emerald-500" size={28} />
          <div>
            <h1 className="font-bold text-lg tracking-tight text-white">CRA Auditor</h1>
            <p className="text-xs text-slate-500">HA Compliance Add-on</p>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          <NavItem id="dashboard" label="Overview" icon={LayoutDashboard} />
          <NavItem id="devices" label="Device Audit" icon={List} />
          <NavItem id="history" label="Scan History" icon={History} />
        </nav>

        <div className="p-4 border-t border-slate-800">
          <div className="bg-slate-800 rounded-lg p-4">
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 block">
              Scan Target (CIDR)
            </label>
            <div className={`flex items-center bg-slate-900 rounded border px-3 py-2 mb-3 transition-colors ${isValidSubnet ? 'border-slate-700' : 'border-red-500/50'
              }`}>
              <input
                type="text"
                value={subnet}
                onChange={(e) => setSubnet(e.target.value)}
                className="bg-transparent border-none text-white text-sm w-full focus:outline-none placeholder-slate-600"
                placeholder="e.g. 192.168.1.0/24"
              />
            </div>
            {!isValidSubnet && subnet.length > 0 && (
              <p className="text-[10px] text-red-400 mb-2 -mt-1">Invalid CIDR format (e.g. 192.168.1.0/24)</p>
            )}
            <button
              onClick={handleScan}
              disabled={scanning || !isValidSubnet}
              className={`w-full flex items-center justify-center gap-2 py-2 rounded font-medium text-sm transition-all ${scanning || !isValidSubnet
                ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-900/20'
                }`}
            >
              {scanning ? <RotateCw className="animate-spin" size={16} /> : <Play size={16} />}
              {scanning ? 'Scanning...' : 'Start Audit'}
            </button>
            <button
              onClick={() => setShowSettings(true)}
              disabled={scanning}
              className="w-full mt-2 flex items-center justify-center gap-2 py-2 rounded font-medium text-sm bg-slate-700 hover:bg-slate-600 text-slate-300 transition-all disabled:opacity-50"
            >
              <Settings size={16} />
              Scan Settings
            </button>
          </div>
        </div>
      </aside>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg shadow-2xl w-full max-w-lg overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-slate-700 bg-slate-800/50">
              <h3 className="font-bold text-white flex items-center gap-2">
                <Settings size={18} className="text-emerald-500" />
                Scan Configuration
              </h3>
              <button onClick={() => setShowSettings(false)} className="text-slate-400 hover:text-white">
                <X size={20} />
              </button>
            </div>

            <div className="p-6 space-y-6">

              {/* Scan Type */}
              <div>
                <label className="block text-sm font-semibold text-slate-300 mb-3">Scan Depth</label>
                <div className="grid grid-cols-3 gap-3">
                  {(['discovery', 'standard', 'deep'] as const).map((type) => (
                    <button
                      key={type}
                      onClick={() => setScanOptions({ ...scanOptions, scan_type: type })}
                      className={`px-3 py-2 rounded border text-sm font-medium capitalize transition-all ${scanOptions.scan_type === type
                        ? 'bg-indigo-600 border-indigo-500 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
                        }`}
                    >
                      {type}
                    </button>
                  ))}
                </div>
                <p className="text-xs text-slate-500 mt-2">
                  {scanOptions.scan_type === 'discovery' && "Fastest. Only checks for device existence (Ping/ARP)."}
                  {scanOptions.scan_type === 'standard' && "Balanced. Checks top 100 ports and services."}
                  {scanOptions.scan_type === 'deep' && "Thorough. OS detection, version probing, top 1000 ports."}
                </p>
              </div>

              {/* Vendors - Only if not discovery */}
              <div className={scanOptions.scan_type === 'discovery' ? 'opacity-50 pointer-events-none' : ''}>
                <label className="block text-sm font-semibold text-slate-300 mb-3">Vendor Detection</label>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => setScanOptions({ ...scanOptions, vendors: 'all' })}
                    className={`px-3 py-1 rounded-full text-xs font-medium border flex items-center gap-2 transition-all ${scanOptions.vendors === 'all'
                      ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400'
                      : 'bg-slate-800 border-slate-700 text-slate-400'
                      }`}
                  >
                    {scanOptions.vendors === 'all' ? <CheckSquare size={12} /> : <Square size={12} />}
                    All Vendors
                  </button>
                  <button
                    onClick={() => setScanOptions({ ...scanOptions, vendors: [] })}
                    className={`px-3 py-1 rounded-full text-xs font-medium border flex items-center gap-2 transition-all ${Array.isArray(scanOptions.vendors) && scanOptions.vendors.length === 0
                      ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400'
                      : 'bg-slate-800 border-slate-700 text-slate-400'
                      }`}
                  >
                    {Array.isArray(scanOptions.vendors) && scanOptions.vendors.length === 0 ? <CheckSquare size={12} /> : <Square size={12} />}
                    No Vendors
                  </button>
                  {['tuya', 'shelly', 'hue', 'kasa', 'sonoff', 'ikea'].map(vendor => {
                    const isSelected = scanOptions.vendors === 'all' || (Array.isArray(scanOptions.vendors) && scanOptions.vendors.includes(vendor));
                    return (
                      <button
                        key={vendor}
                        onClick={() => {
                          let current = scanOptions.vendors;
                          if (current === 'all') {
                            // Switch to select mode, unselect this one? No, if clicking specific, maybe desire is to toggle.
                            // Logic: If 'all', and user clicks 'tuya', change to everything BUT tuya? Or just tuya? 
                            // Let's assume clicking a specific vendor when 'all' is selected means "I only want this one".
                            current = [vendor];
                          } else {
                            if (current.includes(vendor)) {
                              current = current.filter(v => v !== vendor);
                              if (current.length === 0) current = 'all'; // Fallback to all if none? or empty?
                            } else {
                              current = [...current, vendor];
                            }
                          }
                          setScanOptions({ ...scanOptions, vendors: current });
                        }}
                        className={`px-3 py-1 rounded-full text-xs font-medium border flex items-center gap-2 transition-all capitalize ${isSelected
                          ? 'bg-indigo-500/10 border-indigo-500 text-indigo-400'
                          : 'bg-slate-800 border-slate-700 text-slate-400'
                          }`}
                      >
                        {isSelected ? <CheckSquare size={12} /> : <Square size={12} />}
                        {vendor}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Auth Checks */}
              <div className={scanOptions.scan_type === 'discovery' ? 'opacity-50 pointer-events-none' : ''}>
                <label className="flex items-center gap-3 p-3 rounded bg-slate-800 border border-slate-700 cursor-pointer hover:bg-slate-700/50 transition-colors">
                  <div
                    className={`w-5 h-5 rounded flex items-center justify-center border transition-colors ${scanOptions.auth_checks ? 'bg-emerald-500 border-emerald-500 text-white' : 'border-slate-500'
                      }`}
                    onClick={() => setScanOptions({ ...scanOptions, auth_checks: !scanOptions.auth_checks })}
                  >
                    {scanOptions.auth_checks && <CheckSquare size={14} />}
                  </div>
                  <div onClick={() => setScanOptions({ ...scanOptions, auth_checks: !scanOptions.auth_checks })}>
                    <div className="text-sm font-medium text-slate-200">Active Vulnerability Probing</div>
                    <div className="text-xs text-slate-500">Attempt safe default credential logins (Telnet) and unauth API access.</div>
                  </div>
                </label>
              </div>

            </div>

            <div className="p-4 border-t border-slate-700 bg-slate-800/50 flex justify-end">
              <button
                onClick={() => setShowSettings(false)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-sm font-medium transition-colors"
              >
                Save & Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 ml-64">
        {/* Header */}
        <header className="h-16 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between px-8 sticky top-0 backdrop-blur-sm z-10">
          <div className="flex items-center gap-4">
            <h2 className="text-xl font-semibold text-white capitalize">
              {view === 'history' ? 'Previous Scans' : view}
            </h2>
            {report && view !== 'history' && (
              <span className="px-3 py-1 rounded-full bg-slate-800 text-xs text-slate-400 border border-slate-700 flex items-center gap-2">
                <Activity size={12} className="text-emerald-500" />
                Last Scan: {new Date(report.timestamp).toLocaleTimeString()}
              </span>
            )}
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              System Active
            </div>
          </div>
        </header>

        {/* View Container */}
        <div className="p-8">
          {loading ? (
            <div className="h-[60vh] flex flex-col items-center justify-center space-y-4">
              <div className="w-12 h-12 border-4 border-slate-700 border-t-indigo-500 rounded-full animate-spin"></div>
              <p className="text-slate-400">Connecting to backend...</p>
            </div>
          ) : scanning ? (
            <div className="h-[60vh] flex flex-col items-center justify-center space-y-4">
              <div className="relative">
                <div className="w-16 h-16 border-4 border-slate-700 border-t-emerald-500 rounded-full animate-spin"></div>
                <div className="absolute top-0 left-0 w-16 h-16 border-4 border-transparent border-b-emerald-500/30 rounded-full animate-spin reverse"></div>
              </div>
              <p className="text-slate-400 animate-pulse">Auditing Network Segment {subnet}...</p>
              <div className="text-xs text-slate-500 font-mono">
                Checking Ports... Verifying CVEs... Testing Auth...
              </div>
            </div>
          ) : (
            <>
              {view === 'dashboard' && report && <Dashboard report={report} geminiEnabled={config?.gemini_enabled} />}
              {view === 'devices' && report && <DeviceList devices={report.devices} />}
              {view === 'history' && <HistoryView onViewReport={handleViewReport} />}
              {scanError && !scanning && (
                <div className="mb-6 p-4 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-start gap-3">
                  <AlertTriangle size={20} className="text-rose-400 mt-0.5 shrink-0" />
                  <div>
                    <h4 className="font-medium text-rose-400 mb-1">Scan Failed</h4>
                    <p className="text-sm text-slate-400">{scanError}</p>
                  </div>
                  <button onClick={() => setScanError(null)} className="ml-auto text-slate-500 hover:text-white">
                    <X size={16} />
                  </button>
                </div>
              )}
              {!report && view !== 'history' && !scanning && (
                <div className="text-center py-20">
                  <div className="inline-block p-4 rounded-full bg-slate-800 mb-4 text-slate-500">
                    <ShieldCheck size={48} />
                  </div>
                  <h3 className="text-xl font-bold text-white mb-2">Ready to Scan</h3>
                  <p className="text-slate-400 max-w-md mx-auto">
                    Enter your target subnet in the sidebar and click "Start Audit" to generate a CRA Compliance Report.
                  </p>
                </div>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
};

export default App;
