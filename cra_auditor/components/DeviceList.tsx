import React, { useState } from 'react';
import { Device, ComplianceStatus } from '../types';
import { AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Cpu, Server, Lock, Bot } from 'lucide-react';
import { getRemediationAdvice } from '../services/geminiService';

interface DeviceListProps {
  devices: Device[];
}

const DeviceRow: React.FC<{ device: Device }> = ({ device }) => {
  const [expanded, setExpanded] = useState(false);
  const [loadingAdvice, setLoadingAdvice] = useState(false);
  const [advice, setAdvice] = useState<string | null>(null);

  const statusColor = {
    [ComplianceStatus.COMPLIANT]: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    [ComplianceStatus.WARNING]: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    [ComplianceStatus.NON_COMPLIANT]: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
  };

  const handleGetAdvice = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (advice) return;
    setLoadingAdvice(true);
    const result = await getRemediationAdvice(device);
    setAdvice(result);
    setLoadingAdvice(false);
  };

  return (
    <>
      <tr 
        className={`border-b border-slate-700 hover:bg-slate-700/30 transition-colors cursor-pointer ${expanded ? 'bg-slate-700/30' : ''}`}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="p-4 flex items-center gap-3">
          <div className="p-2 rounded bg-slate-800 text-slate-300">
            <Server size={18} />
          </div>
          <div>
            <div className="font-medium text-white">{device.hostname}</div>
            <div className="text-xs text-slate-400">{device.ip}</div>
          </div>
        </td>
        <td className="p-4 text-slate-300">{device.vendor}</td>
        <td className="p-4 font-mono text-sm text-slate-400">{device.mac}</td>
        <td className="p-4">
          <span className={`px-3 py-1 rounded-full text-xs font-medium border ${statusColor[device.status]}`}>
            {device.status}
          </span>
        </td>
        <td className="p-4 text-right text-slate-400">
          {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </td>
      </tr>
      
      {expanded && (
        <tr className="bg-slate-800/50">
          <td colSpan={5} className="p-6 border-b border-slate-700">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
              {/* Check 1: Secure by Default */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <Lock size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Secure Defaults</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {device.checks.secureByDefault.passed 
                    ? <CheckCircle size={16} className="text-emerald-500" /> 
                    : <XCircle size={16} className="text-rose-500" />}
                  <span className={`text-sm ${device.checks.secureByDefault.passed ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {device.checks.secureByDefault.passed ? 'Passed' : 'Failed'}
                  </span>
                </div>
                <p className="text-xs text-slate-500">{device.checks.secureByDefault.details}</p>
              </div>

              {/* Check 2: Confidentiality */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Encryption</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {device.checks.dataConfidentiality.passed 
                    ? <CheckCircle size={16} className="text-emerald-500" /> 
                    : <AlertTriangle size={16} className="text-amber-500" />}
                  <span className={`text-sm ${device.checks.dataConfidentiality.passed ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {device.checks.dataConfidentiality.passed ? 'Passed' : 'Warning'}
                  </span>
                </div>
                 <p className="text-xs text-slate-500">{device.checks.dataConfidentiality.details}</p>
              </div>

              {/* Check 3: CVEs */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <Cpu size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Vulnerabilities</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {device.checks.vulnerabilities.passed 
                    ? <CheckCircle size={16} className="text-emerald-500" /> 
                    : <XCircle size={16} className="text-rose-500" />}
                  <span className={`text-sm ${device.checks.vulnerabilities.passed ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {device.checks.vulnerabilities.passed ? 'Passed' : 'Critical Found'}
                  </span>
                </div>
                <div className="text-xs text-slate-500">
                   {device.checks.vulnerabilities.cves.length > 0 ? (
                      <ul className="list-disc ml-4 space-y-1 mt-1">
                        {device.checks.vulnerabilities.cves.map(cve => (
                          <li key={cve.id} className="text-rose-400">{cve.id} ({cve.severity})</li>
                        ))}
                      </ul>
                   ) : "No known vulnerabilities found."}
                </div>
              </div>
            </div>

            {/* Remediation Section */}
            {device.status !== ComplianceStatus.COMPLIANT && (
              <div className="mt-4 border-t border-slate-700 pt-4">
                 <button 
                  onClick={handleGetAdvice}
                  disabled={loadingAdvice}
                  className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-sm font-medium disabled:opacity-50 transition-colors"
                 >
                   <Bot size={16} />
                   {loadingAdvice ? "Consulting AI Expert..." : "Ask AI for Remediation Plan"}
                 </button>
                 
                 {advice && (
                   <div className="mt-4 p-4 bg-slate-900 rounded border border-indigo-500/30 text-slate-300 text-sm leading-relaxed whitespace-pre-wrap font-mono">
                     {advice}
                   </div>
                 )}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
};

const DeviceList: React.FC<DeviceListProps> = ({ devices }) => {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden shadow-lg">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-900/50 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-700">
              <th className="p-4 font-semibold">Device</th>
              <th className="p-4 font-semibold">Vendor</th>
              <th className="p-4 font-semibold">MAC Address</th>
              <th className="p-4 font-semibold">CRA Status</th>
              <th className="p-4"></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((device, idx) => (
              <DeviceRow key={`${device.mac}-${idx}`} device={device} />
            ))}
            {devices.length === 0 && (
              <tr>
                <td colSpan={5} className="p-8 text-center text-slate-500">
                  No devices found. Run a scan to populate list.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default DeviceList;