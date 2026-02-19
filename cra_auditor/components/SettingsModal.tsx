import React from 'react';
import { CheckSquare, Settings, Square, X } from 'lucide-react';
import TechButton from './ui/TechButton';
import { useLanguage } from '../LanguageContext';
import { ScanOptions, UserMode } from '../types';

interface SettingsModalProps {
  show: boolean;
  scanning: boolean;
  mode: UserMode;
  scanOptions: ScanOptions;
  onClose: () => void;
  onScanOptionsChange: (nextOptions: ScanOptions) => void;
}

const SettingsModal: React.FC<SettingsModalProps> = ({
  show,
  scanning,
  mode,
  scanOptions,
  onClose,
  onScanOptionsChange
}) => {
  const { t } = useLanguage();

  if (!show) {
    return null;
  }

  const applyScanType = (scan_type: ScanOptions['scan_type']) => {
    onScanOptionsChange({ ...scanOptions, scan_type });
  };

  const endUserDepthOptions: Array<{ label: string; value: ScanOptions['scan_type'] }> = [
    { label: t('settings.depth.basic'), value: 'standard' },
    { label: t('settings.depth.deep'), value: 'deep' }
  ];

  const depthLabel = (type: ScanOptions['scan_type']): string => {
    if (type === 'discovery') return t('settings.depth.discovery');
    if (type === 'standard') return t('settings.depth.standard');
    return t('settings.depth.deep');
  };

  const modeLabel = (): string => {
    if (mode === 'basic') return t('mode.basic');
    if (mode === 'intermediate') return t('mode.intermediate');
    return t('mode.expert');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-2xl overflow-hidden rounded-2xl border border-slate-700/80 bg-slate-900/95 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-700/70 bg-slate-800/60 p-4">
          <h3 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-cyan-200">
            <Settings size={16} /> {t('settings.title')}
          </h3>
          <button onClick={onClose} className="text-slate-400 transition hover:text-white">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-5 p-6">
          <div>
            <label className="mb-2 block text-sm font-semibold uppercase tracking-wider text-slate-300">{t('settings.experienceLevel')}</label>
            <div className="rounded-xl border border-slate-700 bg-slate-800/70 px-3 py-2 text-sm text-slate-200">
              <span className="font-semibold">{modeLabel()}</span>
              <span className="ml-2 text-xs text-slate-400">{t('settings.levelHint')}</span>
            </div>
          </div>

          {mode === 'basic' && (
            <div>
              <label className="mb-2 block text-sm font-semibold uppercase tracking-wider text-slate-300">{t('settings.scanDepth')}</label>
              <div className="grid grid-cols-2 gap-2">
                {endUserDepthOptions.map((option) => (
                  <button
                    key={option.value}
                    disabled={scanning}
                    onClick={() => applyScanType(option.value)}
                    className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${scanOptions.scan_type === option.value
                      ? 'border-cyan-400/50 bg-cyan-500/20 text-cyan-200'
                      : 'border-slate-700 bg-slate-800/70 text-slate-300 hover:text-white'
                      } ${scanning ? 'opacity-60 cursor-not-allowed' : ''}`}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {mode !== 'basic' && (
            <div>
              <label className="mb-2 block text-sm font-semibold uppercase tracking-wider text-slate-300">{t('settings.scanDepth')}</label>
              <div className="grid grid-cols-3 gap-2">
                {(['discovery', 'standard', 'deep'] as const).map((type) => (
                  <button
                    key={type}
                    disabled={scanning}
                    onClick={() => applyScanType(type)}
                    className={`rounded-lg border px-3 py-2 text-sm font-semibold capitalize transition ${scanOptions.scan_type === type
                      ? 'border-cyan-400/50 bg-cyan-500/20 text-cyan-200'
                      : 'border-slate-700 bg-slate-800/70 text-slate-300 hover:text-white'
                      } ${scanning ? 'opacity-60 cursor-not-allowed' : ''}`}
                  >
                    {depthLabel(type)}
                  </button>
                ))}
              </div>
            </div>
          )}

          {((mode === 'basic' && scanOptions.scan_type === 'deep') || mode !== 'basic') && (
            <div className={mode !== 'basic' && scanOptions.scan_type === 'discovery' ? 'pointer-events-none opacity-50' : ''}>
              <label className="mb-2 block text-sm font-semibold uppercase tracking-wider text-slate-300">{t('settings.vendorDetection')}</label>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => onScanOptionsChange({ ...scanOptions, vendors: 'all' })}
                  className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-semibold transition ${scanOptions.vendors === 'all'
                    ? 'border-emerald-400/40 bg-emerald-500/20 text-emerald-200'
                    : 'border-slate-700 bg-slate-800/70 text-slate-300'
                    }`}
                >
                  {scanOptions.vendors === 'all' ? <CheckSquare size={12} /> : <Square size={12} />}
                  {t('settings.vendors.all')}
                </button>
                <button
                  onClick={() => onScanOptionsChange({ ...scanOptions, vendors: [] })}
                  className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-semibold transition ${Array.isArray(scanOptions.vendors) && scanOptions.vendors.length === 0
                    ? 'border-emerald-400/40 bg-emerald-500/20 text-emerald-200'
                    : 'border-slate-700 bg-slate-800/70 text-slate-300'
                    }`}
                >
                  {Array.isArray(scanOptions.vendors) && scanOptions.vendors.length === 0 ? <CheckSquare size={12} /> : <Square size={12} />}
                  {t('settings.vendors.none')}
                </button>
                {['tuya', 'shelly', 'hue', 'kasa', 'sonoff', 'ikea'].map((vendor) => {
                  const selected = scanOptions.vendors === 'all' || (Array.isArray(scanOptions.vendors) && scanOptions.vendors.includes(vendor));
                  return (
                    <button
                      key={vendor}
                      onClick={() => {
                        let current = scanOptions.vendors;
                        if (current === 'all') {
                          current = [vendor];
                        } else {
                          if (!Array.isArray(current)) {
                            current = [];
                          }
                          if (current.includes(vendor)) {
                            current = current.filter((value) => value !== vendor);
                            if (current.length === 0) current = [];
                          } else {
                            current = [...current, vendor];
                          }
                        }
                        onScanOptionsChange({ ...scanOptions, vendors: current });
                      }}
                      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-semibold capitalize transition ${selected
                        ? 'border-violet-400/40 bg-violet-500/20 text-violet-200'
                        : 'border-slate-700 bg-slate-800/70 text-slate-300'
                        }`}
                    >
                      {selected ? <CheckSquare size={12} /> : <Square size={12} />}
                      {vendor}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {mode === 'expert' && (
            <div className={scanOptions.scan_type === 'discovery' ? 'pointer-events-none opacity-50' : ''}>
              <label className="flex items-start gap-3 rounded-xl border border-slate-700 bg-slate-800/70 p-3">
                <input
                  type="checkbox"
                  checked={Boolean(scanOptions.auth_checks)}
                  onChange={() => onScanOptionsChange({ ...scanOptions, auth_checks: !scanOptions.auth_checks })}
                  className="mt-0.5"
                />
                <div>
                  <div className="text-sm font-medium text-slate-100">{t('settings.activeProbing.title')}</div>
                  <div className="text-sm text-slate-300">{t('settings.activeProbing.description')}</div>
                </div>
              </label>
            </div>
          )}
        </div>

        <div className="flex justify-end border-t border-slate-700/70 bg-slate-800/60 p-4">
          <TechButton onClick={onClose} variant="primary">{t('settings.saveClose')}</TechButton>
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;
