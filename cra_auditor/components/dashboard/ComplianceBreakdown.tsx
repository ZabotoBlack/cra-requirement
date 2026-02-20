import React, { useMemo } from 'react';
import { CheckCircle2, AlertTriangle, Minus, XCircle } from 'lucide-react';
import { Device } from '../../types';
import { useLanguage } from '../../LanguageContext';
import GlassCard from '../ui/GlassCard';

interface ComplianceBreakdownProps {
    devices: Device[];
}

const ComplianceBreakdown: React.FC<ComplianceBreakdownProps> = ({ devices }) => {
    const { t } = useLanguage();

    const renderStatusIcon = (passed?: boolean, details?: string) => {
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

        // If it failed, show a red X or warning triangle depending on details (heuristically, warning if just minor)
        // Actually, following the "Warning / Non-Compliant" requirement:
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

    const rows = useMemo(() => {
        return devices.map((device) => ({
            key: `${device.mac}-${device.ip}`,
            hostname: device.hostname || t('deviceList.unknownHostname'),
            ip: device.ip,
            checks: device.checks || {}
        }));
    }, [devices, t]);

    return (
        <GlassCard className="rounded-2xl p-5 overflow-hidden">
            <div className="mb-4">
                <h3 className="text-muted text-sm font-semibold uppercase tracking-wider">{t('dashboard.complianceBreakdown')}</h3>
            </div>
            <div className="overflow-x-auto">
                <table className="w-full text-left min-w-[600px]">
                    <thead>
                        <tr className="border-b border-slate-800 bg-slate-950/70 text-xs uppercase tracking-wider text-slate-300">
                            <th className="px-4 py-3">{t('dashboard.device')}</th>
                            <th className="px-2 py-3 text-center">{t('dashboard.check.defaults')}</th>
                            <th className="px-2 py-3 text-center">{t('dashboard.check.encryption')}</th>
                            <th className="px-2 py-3 text-center">{t('dashboard.check.vulnerabilities')}</th>
                            <th className="px-2 py-3 text-center">{t('dashboard.check.sbom')}</th>
                            <th className="px-2 py-3 text-center">{t('dashboard.check.logging')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((row) => (
                            <tr key={row.key} className="border-b border-slate-800/70 hover:bg-slate-900/45 transition-colors">
                                <td className="px-4 py-3">
                                    <p className="font-semibold text-main text-sm truncate max-w-[180px]" title={row.hostname}>
                                        {row.hostname}
                                    </p>
                                    <p className="text-xs text-soft font-mono">{row.ip}</p>
                                </td>
                                <td className="px-2 py-3">
                                    {renderStatusIcon(row.checks.secureByDefault?.passed, row.checks.secureByDefault?.details)}
                                </td>
                                <td className="px-2 py-3">
                                    {renderStatusIcon(row.checks.dataConfidentiality?.passed, row.checks.dataConfidentiality?.details)}
                                </td>
                                <td className="px-2 py-3">
                                    {renderStatusIcon(row.checks.vulnerabilities?.passed, row.checks.vulnerabilities?.details)}
                                </td>
                                <td className="px-2 py-3">
                                    {renderStatusIcon(row.checks.sbomCompliance?.passed, row.checks.sbomCompliance?.details)}
                                </td>
                                <td className="px-2 py-3">
                                    {renderStatusIcon(row.checks.securityLogging?.passed, row.checks.securityLogging?.details)}
                                </td>
                            </tr>
                        ))}
                        {rows.length === 0 && (
                            <tr>
                                <td colSpan={6} className="px-6 py-8 text-center text-sm text-slate-500">
                                    {t('deviceList.empty.noDevices')}
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </GlassCard>
    );
};

export default ComplianceBreakdown;
