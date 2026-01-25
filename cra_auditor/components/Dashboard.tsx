import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import { ScanReport, ComplianceStatus } from '../types';
import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';

interface DashboardProps {
  report: ScanReport;
}

const COLORS = {
  [ComplianceStatus.COMPLIANT]: '#10b981', // emerald-500
  [ComplianceStatus.WARNING]: '#f59e0b',   // amber-500
  [ComplianceStatus.NON_COMPLIANT]: '#f43f5e' // rose-500
};

const Dashboard: React.FC<DashboardProps> = ({ report }) => {
  const pieData = [
    { name: 'Compliant', value: report.summary.compliant },
    { name: 'Warning', value: report.summary.warning },
    { name: 'Non-Compliant', value: report.summary.nonCompliant },
  ].filter(d => d.value > 0);

  // Vendor Vulnerability Distribution
  const vendorDataMap = new Map<string, number>();
  report.devices.forEach(d => {
    if (d.status !== ComplianceStatus.COMPLIANT) {
      vendorDataMap.set(d.vendor, (vendorDataMap.get(d.vendor) || 0) + 1);
    }
  });
  
  const barData = Array.from(vendorDataMap.entries()).map(([name, count]) => ({ name, count }));

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
        <Card 
          title="Non-Compliant" 
          value={report.summary.nonCompliant} 
          sub="Critical Failures"
          icon={ShieldAlert}
          color="text-rose-400"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Compliance Distribution */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Compliance Distribution</h3>
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

        {/* Vendor Risk Analysis */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Risks by Vendor</h3>
          {barData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                  <XAxis type="number" stroke="#94a3b8" />
                  <YAxis dataKey="name" type="category" width={100} stroke="#94a3b8" style={{ fontSize: '12px' }} />
                  <Tooltip 
                    cursor={{fill: '#334155', opacity: 0.4}}
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#fff' }}
                  />
                  <Bar dataKey="count" fill="#f43f5e" radius={[0, 4, 4, 0]} />
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
    </div>
  );
};

export default Dashboard;
