import React from 'react';
import { useLanguage, SUPPORTED_LANGUAGES } from '../LanguageContext';

const LanguageSelector: React.FC = () => {
  const { language, setLanguage, t } = useLanguage();

  return (
    <div className="surface-card mt-2 rounded-xl border p-3">
      <label className="text-soft mb-2 block text-[11px] font-semibold uppercase tracking-widest">{t('sidebar.language')}</label>
      <select
        value={language}
        onChange={(event) => setLanguage(event.target.value === 'de' ? 'de' : 'en')}
        className="surface-elevated text-main w-full rounded-xl border px-2 py-2 text-sm outline-none transition focus:border-[var(--color-accent-border)]"
      >
        {SUPPORTED_LANGUAGES.map((option) => (
          <option key={option.code} value={option.code}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
};

export default LanguageSelector;
