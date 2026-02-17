import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import { ScanReport, ComplianceStatus } from '../types';
import { ShieldAlert, ShieldCheck, ShieldQuestion, Sparkles } from 'lucide-react';

interface DashboardProps {
  report: ScanReport;
  geminiEnabled?: boolean;
  nvdEnabled?: boolean;
}

const COLORS = {
  [ComplianceStatus.COMPLIANT]: '#10b981', // emerald-500
  [ComplianceStatus.WARNING]: '#f59e0b',   // amber-500
  [ComplianceStatus.NON_COMPLIANT]: '#f43f5e' // rose-500
};

const Dashboard: React.FC<DashboardProps> = ({ report, geminiEnabled, nvdEnabled }) => {
  const pieData = [
    { name: 'Compliant', value: report.summary.compliant },
    { name: 'Warning', value: report.summary.warning },
    { name: 'Non-Compliant', value: report.summary.nonCompliant },
  ].filter(d => d.value > 0);

  // 1. Vendor Vulnerability Distribution (Improved)
  const vendorDataMap = new Map<string, number>();
  report.devices.forEach(d => {
    if (d.status !== ComplianceStatus.COMPLIANT) {
      // Clean vendor name
      let v = d.vendor.split('(')[0].trim();
      if (v === 'Unknown' && d.osMatch !== 'Unknown') v = `Unknown (${d.osMatch})`;
      vendorDataMap.set(v, (vendorDataMap.get(v) || 0) + 1);
    }
  });

  // Sort by count desc, take top 7
  const barData = Array.from(vendorDataMap.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 7);

  // 2. Common Services (New)
  const serviceMap = new Map<string, number>();
  report.devices.forEach(d => {
    if (d.openPorts) {
      d.openPorts.forEach(p => {
        serviceMap.set(p.service, (serviceMap.get(p.service) || 0) + 1);
      });
    }
  });
  const serviceData = Array.from(serviceMap.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // 3. OS Distribution (New)
  const osMap = new Map<string, number>();
  report.devices.forEach(d => {
    const os = d.osMatch === 'Unknown' ? 'Unknown OS' : d.osMatch;
    osMap.set(os, (osMap.get(os) || 0) + 1);
  });
  const osData = Array.from(osMap.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  const Card = ({ title, value, sub, icon: Icon, color }: any) => (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 flex items-start justify-between shadow-lg">
      <div>
        <p className="text-slate-400 text-sm font-medium mb-1">{title}</p>
        <h3 className="text-3xl font-bold text-white">{value}</h3>
        {sub && <p className="text-xs text-slate-500 mt-2">{sub}</p>}
      </div>
      <div className={`p-3 rounded-full bg-slate-700/50 ${color}`}>
        <Icon size={24} />
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card
          title="Total Devices"
          value={report.summary.total}
          sub={`Scanned: ${report.targetRange}`}
          icon={ShieldQuestion}
          color="text-blue-400"
        />
        <Card
          title="Compliant"
          value={report.summary.compliant}
          sub="Passed Annex I Checks"
          icon={ShieldCheck}
          color="text-emerald-400"
        />
        <Card
          title="Warnings"
          value={report.summary.warning}
          sub="Encryption Issues"
          icon={ShieldAlert}
          color="text-amber-400"
        />
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 flex items-start justify-between shadow-lg">
          <div>
            <p className="text-slate-400 text-sm font-medium mb-1">AI Insights</p>
            <h3 className="text-xl font-bold text-white mt-1">
              {geminiEnabled ? 'Active' : 'Disabled'}
            </h3>
            <p className="text-xs text-slate-500 mt-2">
              {geminiEnabled ? 'Gemini Pro Connected' : 'Add Key in Config'}
            </p>
            <div className="mt-2">
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${nvdEnabled ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' : 'text-rose-400 border-rose-500/40 bg-rose-500/10'}`}>
                NVD {nvdEnabled ? 'Active' : 'Disabled'}
              </span>
            </div>
          </div>
          <div className={`p-3 rounded-full bg-slate-700/50 ${geminiEnabled ? 'text-purple-400' : 'text-slate-500'}`}>
            <Sparkles size={24} />
          </div>
        </div>
      </div>

      {/* Row 1: Compliance & Vendor Risks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Compliance Distribution */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Compliance Status</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.name as ComplianceStatus]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#fff' }}
                  itemStyle={{ color: '#fff' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-4 mt-2">
            {pieData.map((entry) => (
              <div key={entry.name} className="flex items-center gap-2 text-sm text-slate-300">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[entry.name as ComplianceStatus] }} />
                {entry.name} ({entry.value})
              </div>
            ))}
          </div>
        </div>

        {/* Vendor Risk Analysis (Improved) */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Top Risks by Vendor</h3>
          {barData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} layout="vertical" margin={{ left: 40, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                  <XAxis type="number" stroke="#94a3b8" />
                  <YAxis dataKey="name" type="category" width={110} stroke="#94a3b8" style={{ fontSize: '11px', fontWeight: 500 }} />
                  <Tooltip
                    cursor={{ fill: '#334155', opacity: 0.4 }}
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#fff' }}
                  />
                  <Bar dataKey="count" fill="#f43f5e" radius={[0, 4, 4, 0]} barSize={20} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-slate-500">
              No High Risk Vendors Found
            </div>
          )}
        </div>
      </div>

      {/* Row 2: Services & OS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Common Services */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Top 5 Detected Services</h3>
          {serviceData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={serviceData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                  <XAxis dataKey="name" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: '#334155', opacity: 0.4 }}
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#fff' }}
                  />
                  <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} barSize={40} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-slate-500">
              No Services Detected
            </div>
          )}
        </div>

        {/* OS Distribution */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">OS Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={osData}
                  cx="50%"
                  cy="50%"
                  innerRadius={0}
                  outerRadius={80}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {osData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={['#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#14b8a6'][index % 5]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#fff' }}
                  itemStyle={{ color: '#fff' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap justify-center gap-x-4 gap-y-2 mt-2">
            {osData.slice(0, 5).map((entry, index) => (
              <div key={entry.name} className="flex items-center gap-2 text-xs text-slate-300">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: ['#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#14b8a6'][index % 5] }} />
                {entry.name}
              </div>
            ))}
          </div>
        </div>
      </div>

    </div>
  );
};

export default Dashboard;
