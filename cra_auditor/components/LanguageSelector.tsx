import React, { useEffect, useRef, useState } from 'react';
import { useLanguage, SUPPORTED_LANGUAGES } from '../LanguageContext';

const LanguageSelector: React.FC = () => {
  const { language, setLanguage, t } = useLanguage();
  const [isLanguageMenuOpen, setIsLanguageMenuOpen] = useState(false);
  const languageMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!isLanguageMenuOpen) {
      return;
    }

    const handlePointerDown = (event: MouseEvent) => {
      if (!languageMenuRef.current?.contains(event.target as Node)) {
        setIsLanguageMenuOpen(false);
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsLanguageMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isLanguageMenuOpen]);

  const currentLabel = SUPPORTED_LANGUAGES.find((option) => option.code === language)?.label || 'English';

  return (
    <div className="surface-card mt-2 rounded-xl border p-3">
      <label className="text-soft mb-2 block text-[11px] font-semibold uppercase tracking-widest">{t('sidebar.language')}</label>
      <div ref={languageMenuRef} className="relative">
        <button
          type="button"
          aria-haspopup="listbox"
          aria-expanded={isLanguageMenuOpen}
          onClick={() => setIsLanguageMenuOpen((prev) => !prev)}
          className="surface-elevated text-main flex w-full items-center justify-between rounded-xl border px-2 py-2 text-sm outline-none transition focus:border-[var(--color-accent-border)]"
        >
          <span>{currentLabel}</span>
          <span className="text-soft text-xs">▾</span>
        </button>
        {isLanguageMenuOpen && (
          <div className="surface-elevated absolute z-20 mt-2 w-full overflow-hidden rounded-xl border" role="listbox" aria-label={t('sidebar.languageOptions')}>
            {SUPPORTED_LANGUAGES.map((option) => (
              <button
                key={option.code}
                type="button"
                role="option"
                aria-selected={language === option.code}
                onClick={() => {
                  setLanguage(option.code);
                  setIsLanguageMenuOpen(false);
                }}
                className={`text-main hover:bg-[var(--panel-hover)] w-full px-3 py-2 text-left text-sm transition ${language === option.code ? 'bg-[var(--panel-selected)] font-semibold' : ''}`}
              >
                {option.label}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default LanguageSelector;
