import { activity, FileCode, LayoutDashboard, List, Play, RotateCw, ShieldCheck } from 'lucide-react';
import React, { useEffect, useState, useRef } from 'react';
import Dashboard from './components/Dashboard';
import DeviceList from './components/DeviceList';
import InstallationGuide from './components/InstallationGuide';
import { startScan, getScanStatus, getReport } from './services/api';
import { ScanReport, ViewState } from './types';

const App: React.FC = () => {
  const [view, setView] = useState<ViewState>('dashboard');
  const [scanning, setScanning] = useState(false);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [subnet, setSubnet] = useState('192.168.1.0/24');
  const pollInterval = useRef<NodeJS.Timeout | null>(null);

  const fetchData = async () => {
    const scanStatus = await getScanStatus();
    setScanning(scanStatus);
    const data = await getReport();
    if (data) setReport(data);
  };

  // Initial load and polling setup
  useEffect(() => {
    fetchData();
    pollInterval.current = setInterval(fetchData, 3000); // Poll every 3 seconds
    return () => {
      if (pollInterval.current) clearInterval(pollInterval.current);
    };
  }, []);

  const handleScan = async () => {
    try {
      setScanning(true);
      setView('dashboard');
      await startScan(subnet);
      // Polling will pick up the status change
    } catch (e) {
      console.error(e);
      setScanning(false);
      alert("Failed to start scan. Check console.");
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
          <NavItem id="installation" label="Backend Setup" icon={FileCode} />
        </nav>

        <div className="p-4 border-t border-slate-800">
          <div className="bg-slate-800 rounded-lg p-4">
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 block">
              Scan Target
            </label>
            <div className="flex items-center bg-slate-900 rounded border border-slate-700 px-3 py-2 mb-3">
              <span className="text-slate-500 mr-1 text-sm">IP:</span>
              <input
                type="text"
                value={subnet}
                onChange={(e) => setSubnet(e.target.value)}
                className="bg-transparent border-none text-white text-sm w-full focus:outline-none placeholder-slate-600"
                placeholder="192.168.1"
              />
              <span className="text-slate-500 text-sm">.0/24</span>
            </div>
            <button
              onClick={handleScan}
              disabled={scanning}
              className={`w-full flex items-center justify-center gap-2 py-2 rounded font-medium text-sm transition-all ${scanning
                  ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-900/20'
                }`}
            >
              {scanning ? <RotateCw className="animate-spin" size={16} /> : <Play size={16} />}
              {scanning ? 'Scanning...' : 'Start Audit'}
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 ml-64">
        {/* Header */}
        <header className="h-16 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between px-8 sticky top-0 backdrop-blur-sm z-10">
          <div className="flex items-center gap-4">
            <h2 className="text-xl font-semibold text-white capitalize">
              {view === 'installation' ? 'Backend Installation Guide' : view}
            </h2>
            {report && view !== 'installation' && (
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
          {scanning && view !== 'installation' ? (
            <div className="h-[60vh] flex flex-col items-center justify-center space-y-4">
              <div className="relative">
                <div className="w-16 h-16 border-4 border-slate-700 border-t-emerald-500 rounded-full animate-spin"></div>
                <div className="absolute top-0 left-0 w-16 h-16 border-4 border-transparent border-b-emerald-500/30 rounded-full animate-spin reverse"></div>
              </div>
              <p className="text-slate-400 animate-pulse">Auditing Network Segment {subnet}.0/24...</p>
              <div className="text-xs text-slate-500 font-mono">
                Checking Ports... Verifying CVEs... Testing Auth...
              </div>
            </div>
          ) : (
            <>
              {view === 'dashboard' && report && <Dashboard report={report} />}
              {view === 'devices' && report && <DeviceList devices={report.devices} />}
              {view === 'installation' && <InstallationGuide />}
              {!report && view !== 'installation' && !scanning && (
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
