import React, { useState } from 'react';
import { Device, ComplianceStatus } from '../types';
import { AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Cpu, Server, Lock, Bot, FileText, Wifi, Shield } from 'lucide-react';
import { getRemediationAdvice } from '../services/geminiService';

interface DeviceListProps {
  devices: Device[];
}

const DeviceRow: React.FC<{ device: Device }> = ({ device }) => {
  const [expanded, setExpanded] = useState(false);
  const [loadingAdvice, setLoadingAdvice] = useState(false);
  const [advice, setAdvice] = useState<string | null>(null);

  const statusColor = {
    [ComplianceStatus.DISCOVERED]: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    [ComplianceStatus.COMPLIANT]: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    [ComplianceStatus.WARNING]: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    [ComplianceStatus.NON_COMPLIANT]: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
  };

  const secureByDefault = device.checks?.secureByDefault;
  const dataConfidentiality = device.checks?.dataConfidentiality;
  const vulnerabilities = device.checks?.vulnerabilities;

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
            <div className={`font-medium ${device.hostname ? 'text-white' : 'text-slate-500 italic'}`}>
              {device.hostname || "Unknown Hostname"}
            </div>
            <div className="text-xs text-slate-400">{device.ip}</div>
          </div>
        </td>
        <td className="p-4 text-slate-300">{device.vendor}</td>
        <td className="p-4 font-mono text-sm text-slate-400">{device.mac}</td>
        <td className="p-4">
          <span className={`px-3 py-1 rounded-full text-xs font-medium border ${statusColor[device.status as ComplianceStatus] || 'text-slate-300 bg-slate-500/10 border-slate-500/20'}`}>
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
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-7 gap-6 mb-6">
              {/* Check 1: Secure by Default */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <Lock size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Secure Defaults</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {secureByDefault?.passed
                    ? <CheckCircle size={16} className="text-emerald-500" />
                    : <XCircle size={16} className="text-rose-500" />}
                  <span className={`text-sm ${secureByDefault?.passed ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {secureByDefault?.passed ? 'Passed' : 'Failed'}
                  </span>
                </div>
                <p className="text-xs text-slate-500">{secureByDefault?.details || 'Not evaluated for this scan profile.'}</p>
              </div>

              {/* Check 2: Confidentiality */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Encryption</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {dataConfidentiality?.passed
                    ? <CheckCircle size={16} className="text-emerald-500" />
                    : <AlertTriangle size={16} className="text-amber-500" />}
                  <span className={`text-sm ${dataConfidentiality?.passed ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {dataConfidentiality?.passed ? 'Passed' : 'Warning'}
                  </span>
                </div>
                <p className="text-xs text-slate-500">{dataConfidentiality?.details || 'Not evaluated for this scan profile.'}</p>
              </div>

              {/* Check 3: CVEs */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <Cpu size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Vulnerabilities</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {vulnerabilities?.passed
                    ? <CheckCircle size={16} className="text-emerald-500" />
                    : <XCircle size={16} className="text-rose-500" />}
                  <span className={`text-sm ${vulnerabilities?.passed ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {vulnerabilities?.passed ? 'Passed' : 'Critical Found'}
                  </span>
                </div>
                <div className="text-xs text-slate-500">
                  {vulnerabilities?.cpe && (
                    <p className="text-indigo-400 mb-1 break-all">CPE: {vulnerabilities.cpe}</p>
                  )}
                  {vulnerabilities?.details && (
                    <p className="mb-1">{vulnerabilities.details}</p>
                  )}
                  {vulnerabilities?.cves && vulnerabilities.cves.length > 0 ? (
                    <ul className="list-disc ml-4 space-y-1 mt-1">
                      {vulnerabilities.cves.map(cve => (
                        <li key={cve.id} className="text-rose-400">{cve.id} ({cve.severity})</li>
                      ))}
                    </ul>
                  ) : (vulnerabilities ? "No known vulnerabilities found." : "Not evaluated for this scan profile.")}
                </div>
              </div>

              {/* Check 4: SBOM Compliance */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <FileText size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">SBOM</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {device.checks.sbomCompliance?.passed
                    ? <CheckCircle size={16} className="text-emerald-500" />
                    : <AlertTriangle size={16} className="text-amber-500" />}
                  <span className={`text-sm ${device.checks.sbomCompliance?.passed ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {device.checks.sbomCompliance?.passed ? 'Available' : 'Not Found'}
                  </span>
                </div>
                <p className="text-xs text-slate-500">{device.checks.sbomCompliance?.details}</p>
                {device.checks.sbomCompliance?.sbom_format && (
                  <p className="text-xs text-indigo-400 mt-1">Format: {device.checks.sbomCompliance.sbom_format}</p>
                )}
              </div>

              {/* Check 5: Firmware Tracking */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <Wifi size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Firmware</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {device.checks.firmwareTracking?.passed
                    ? <CheckCircle size={16} className="text-emerald-500" />
                    : <AlertTriangle size={16} className="text-amber-500" />}
                  <span className={`text-sm ${device.checks.firmwareTracking?.passed ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {device.checks.firmwareTracking?.passed ? 'Tracked' : 'Unknown / Vulnerable'}
                  </span>
                </div>
                {device.checks.firmwareTracking?.firmware_version && (
                  <p className="text-xs text-indigo-400 mb-1">
                    Version: {device.checks.firmwareTracking.firmware_version}
                    {device.checks.firmwareTracking.firmware_source && (
                      <span className="text-slate-500"> via {device.checks.firmwareTracking.firmware_source}</span>
                    )}
                  </p>
                )}
                <p className="text-xs text-slate-500">{device.checks.firmwareTracking?.details}</p>
                {device.checks.firmwareTracking?.version_cves && device.checks.firmwareTracking.version_cves.length > 0 && (
                  <ul className="list-disc ml-4 space-y-1 mt-1">
                    {device.checks.firmwareTracking.version_cves.map(cve => (
                      <li key={cve.id} className="text-xs text-rose-400">{cve.id} ({cve.severity})</li>
                    ))}
                  </ul>
                )}
                {device.checks.firmwareTracking?.update_url && (
                  <a
                    href={device.checks.firmwareTracking.update_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-block mt-2 text-xs text-indigo-400 hover:text-indigo-300 underline"
                    onClick={(e) => e.stopPropagation()}
                  >
                    Check for updates &rarr;
                  </a>
                )}
              </div>

              {/* Check 6: Security.txt */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <Shield size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Security.txt</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {device.checks.securityTxt?.passed
                    ? <CheckCircle size={16} className="text-emerald-500" />
                    : <AlertTriangle size={16} className="text-amber-500" />}
                  <span className={`text-sm ${device.checks.securityTxt?.passed ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {device.checks.securityTxt?.passed ? 'Available' : 'Not Found'}
                  </span>
                </div>
                <p className="text-xs text-slate-500">{device.checks.securityTxt?.details}</p>
                {device.checks.securityTxt?.fields?.contact && (
                  <p className="text-xs text-indigo-400 mt-1">Contact: {device.checks.securityTxt.fields.contact}</p>
                )}
                {device.checks.securityTxt?.fields?.policy && (
                  <p className="text-xs text-indigo-400 mt-1">Policy: {device.checks.securityTxt.fields.policy}</p>
                )}
                {device.checks.securityTxt?.vendor_url && !device.checks.securityTxt?.security_txt_found && (
                  <a
                    href={device.checks.securityTxt.vendor_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-block mt-2 text-xs text-indigo-400 hover:text-indigo-300 underline"
                    onClick={(e) => e.stopPropagation()}
                  >
                    Vendor disclosure policy &rarr;
                  </a>
                )}
              </div>

              {/* Check 7: Security Logging */}
              <div className="bg-slate-900 rounded p-4 border border-slate-700">
                <div className="flex items-center gap-2 mb-2">
                  <FileText size={16} className="text-slate-400" />
                  <h4 className="font-medium text-slate-200">Security Logging</h4>
                </div>
                <div className="flex items-center gap-2 mb-1">
                  {device.checks.securityLogging?.passed
                    ? <CheckCircle size={16} className="text-emerald-500" />
                    : <AlertTriangle size={16} className="text-amber-500" />}
                  <span className={`text-sm ${device.checks.securityLogging?.passed ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {device.checks.securityLogging?.passed ? 'Pass' : 'Warning'}
                  </span>
                </div>
                <p className="text-xs text-slate-500">{device.checks.securityLogging?.details}</p>
                {device.checks.securityLogging?.syslog_udp_514 && (
                  <p className="text-xs text-indigo-400 mt-1">UDP/514 reachable</p>
                )}
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
  const [filterText, setFilterText] = useState('');
  const [sortConfig, setSortConfig] = useState<{ key: keyof Device, direction: 'asc' | 'desc' } | null>(null);

  const handleSort = (key: keyof Device) => {
    let direction: 'asc' | 'desc' = 'asc';
    if (sortConfig && sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  const filteredDevices = devices.filter(device =>
    device.hostname.toLowerCase().includes(filterText.toLowerCase()) ||
    device.ip.includes(filterText) ||
    device.vendor.toLowerCase().includes(filterText.toLowerCase())
  );

  // Helper helper to sort IPs numerically
  const compareIPs = (ipA: string, ipB: string) => {
    const numA = ipA.split('.').map(Number);
    const numB = ipB.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if (numA[i] !== numB[i]) return numA[i] - numB[i];
    }
    return 0;
  };

  const sortedDevices = React.useMemo(() => {
    if (!sortConfig) return filteredDevices;
    return [...filteredDevices].sort((a, b) => {
      // Special handling for IP sorting
      if (sortConfig.key === 'ip') {
        return sortConfig.direction === 'asc'
          ? compareIPs(a.ip, b.ip)
          : compareIPs(b.ip, a.ip);
      }

      // Default String sorting
      // @ts-ignore
      if (a[sortConfig.key] < b[sortConfig.key]) {
        return sortConfig.direction === 'asc' ? -1 : 1;
      }
      // @ts-ignore
      if (a[sortConfig.key] > b[sortConfig.key]) {
        return sortConfig.direction === 'asc' ? 1 : -1;
      }
      return 0;
    });
  }, [filteredDevices, sortConfig]);

  const SortIcon = ({ column }: { column: keyof Device }) => {
    if (sortConfig?.key !== column) return <div className="w-4 h-4 ml-1 inline-block opacity-20"><ChevronDown size={14} /></div>;
    return sortConfig.direction === 'asc'
      ? <div className="w-4 h-4 ml-1 inline-block text-emerald-500"><ChevronUp size={14} /></div>
      : <div className="w-4 h-4 ml-1 inline-block text-emerald-500"><ChevronDown size={14} /></div>;
  };

  return (
    <div className="space-y-4">
      {/* Search Filter */}
      <div className="flex justify-between items-center bg-slate-800 p-3 rounded-lg border border-slate-700">
        <input
          type="text"
          placeholder="Filter devices..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="bg-slate-900 border-none rounded text-sm text-slate-200 px-3 py-2 w-full max-w-sm focus:ring-1 focus:ring-indigo-500 placeholder-slate-500"
        />
        <div className="text-xs text-slate-500">
          Showing {sortedDevices.length} of {devices.length} devices
        </div>
      </div>

      <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900/50 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-700">
                <th className="p-4 font-semibold cursor-pointer hover:text-white transition-colors select-none" onClick={() => handleSort('ip')}>
                  Device <SortIcon column="ip" />
                </th>
                <th className="p-4 font-semibold cursor-pointer hover:text-white transition-colors select-none" onClick={() => handleSort('vendor')}>
                  Vendor <SortIcon column="vendor" />
                </th>
                <th className="p-4 font-semibold cursor-pointer hover:text-white transition-colors select-none" onClick={() => handleSort('mac')}>
                  MAC Address <SortIcon column="mac" />
                </th>
                <th className="p-4 font-semibold cursor-pointer hover:text-white transition-colors select-none" onClick={() => handleSort('status')}>
                  CRA Status <SortIcon column="status" />
                </th>
                <th className="p-4"></th>
              </tr>
            </thead>
            <tbody>
              {sortedDevices.map((device, idx) => (
                <DeviceRow key={`${device.mac}-${idx}`} device={device} />
              ))}
              {sortedDevices.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">
                    {devices.length === 0 ? "No devices found. Run a scan to populate list." : "No devices match filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default DeviceList;